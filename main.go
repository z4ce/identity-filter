package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// Config struct to hold a map of identities
type Config struct {
	Identities map[string]Identity `yaml:"identities"`
}

type Identity struct {
	Enabled   bool   `yaml:"enabled"`
	Reason    string `yaml:"reason,omitempty"`
	ExpiresOn string `yaml:"expires-on,omitempty"`
}

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	Version         string  `json:"version"`
	Rules           []Rules `json:"rules"`
}

type Rules struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription ShortDesc `json:"shortDescription"`
}
type ShortDesc struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex"`
	Level        string            `json:"level"`
	Message      Message           `json:"message"`
	Locations    []Location        `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints"`
	CodeFlows    []CodeFlow        `json:"codeFlows"`
	Properties   Properties        `json:"properties"`
}

type Message struct {
	Text      string   `json:"text"`
	Markdown  string   `json:"markdown"`
	Arguments []string `json:"arguments"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

type ThreadFlow struct {
	Locations []ThreadLocation `json:"locations"`
}

type ThreadLocation struct {
	Location Location `json:"location"`
}

type Properties struct {
	PriorityScore        int              `json:"priorityScore"`
	PriorityScoreFactors []PriorityFactor `json:"priorityScoreFactors"`
	IsAutofixable        bool             `json:"isAutofixable"`
}

type PriorityFactor struct {
	Label bool   `json:"label"`
	Type  string `json:"type"`
}

// ... (Rest of the SARIF data structures remain the same) ...

func main() {
	var cmdFilter = &cobra.Command{
		Use:   "filter",
		Short: "Filter identities from SARIF file",
		Run: func(cmd *cobra.Command, args []string) {
			sarifFile, _ := cmd.Flags().GetString("sarif")
			identitiesSource, _ := cmd.Flags().GetString("identities-file")

			if sarifFile == "" || identitiesSource == "" {
				log.Fatal("Please provide both --sarif and --identities-file flags")
			}

			sarifData, err := ioutil.ReadFile(sarifFile)
			if err != nil {
				log.Fatal(err)
			}

			var yamlData []byte
			if strings.HasPrefix(identitiesSource, "http://") || strings.HasPrefix(identitiesSource, "https://") {
				yamlData, err = fetchYAMLFromURL(identitiesSource)
			} else {
				yamlData, err = ioutil.ReadFile(identitiesSource)
			}
			if err != nil {
				log.Fatal(err)
			}

			var config Config
			err = yaml.Unmarshal(yamlData, &config)
			if err != nil {
				log.Fatal(err)
			}

			var sarif Sarif
			err = json.Unmarshal(sarifData, &sarif)
			if err != nil {
				log.Fatal(err)
			}

			currentTime := time.Now() // Get current time

			filteredSarif := filterIdentities(&sarif, config.Identities, currentTime)
			filteredSarifJSON, err := json.MarshalIndent(filteredSarif, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(filteredSarifJSON))
		},
	}

	cmdFilter.Flags().StringP("sarif", "s", "", "Path to the SARIF file")
	cmdFilter.Flags().StringP("identities-file", "i", "", "Path or URL to the YAML file with identities. Format: identities: {fingerprint: bool, ...}")

	var rootCmd = &cobra.Command{
		Use:   "sarif-filter",
		Short: "A tool for filtering identities from SARIF files",
	}

	rootCmd.AddCommand(cmdFilter)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fetchYAMLFromURL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch YAML from URL: %s, status code: %d", url, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func filterIdentities(sarif *Sarif, identities map[string]Identity, currentTime time.Time) *Sarif {
	filteredSarif := &Sarif{
		Schema:  sarif.Schema,
		Version: sarif.Version,
		Runs:    make([]Run, len(sarif.Runs)),
	}

	for i, run := range sarif.Runs {
		filteredRun := Run{
			Tool:    run.Tool,
			Results: filterResults(run.Results, identities, currentTime),
		}
		filteredSarif.Runs[i] = filteredRun
	}

	return filteredSarif
}

func filterResults(results []Result, identities map[string]Identity, currentTime time.Time) []Result {
	var filteredResults []Result

	for _, result := range results {
		identity := result.Fingerprints["identity"]
		if shouldKeepResult(identity, identities, currentTime) {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults
}

func shouldKeepResult(identity string, identities map[string]Identity, currentTime time.Time) bool {
	identityConfig, exists := identities[identity]
	if !exists {
		return true // Keep the result if the identity is not in the config
	}

	if !identityConfig.Enabled {
		return true // Keep the result if the identity is not enabled
	}

	return !isExpired(identityConfig, currentTime)
}

func isExpired(identity Identity, currentTime time.Time) bool {
	if identity.ExpiresOn == "" {
		return false // Not expired if no expiration date is set
	}
	expirationTime, err := time.Parse("2006-01-02", identity.ExpiresOn)
	if err != nil {
		log.Printf("Warning: Invalid expiration date format for identity: %v", err)
		return false
	}
	return currentTime.After(expirationTime)
}
