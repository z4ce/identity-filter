package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestFilterIdentities(t *testing.T) {
	// Test SARIF data (keep the existing SARIF JSON)
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Test Tool",
						"version": "1.0"
					}
				},
				"results": [
					{
						"ruleId": "TEST001",
						"message": {
							"text": "Test result 1"
						},
						"fingerprints": {
							"identity": "84e70d75-2ac2-40ab-8a06-a17a2b5be9f5"
						}
					},
					{
						"ruleId": "TEST002",
						"message": {
							"text": "Test result 2"
						},
						"fingerprints": {
							"identity": "98f76d54-3bc1-50cd-9a07-b28a3c6d8e4f"
						}
					}
				]
			}
		]
	}`

	var sarif Sarif
	err := json.Unmarshal([]byte(sarifJSON), &sarif)
	if err != nil {
		t.Fatalf("Failed to unmarshal test SARIF data: %v", err)
	}

	// New Identity file content
	identitiesYAML := `
identities:
  84e70d75-2ac2-40ab-8a06-a17a2b5be9f5: # should be present because its expired
    enabled: true
    reason: "Test reason"
    expires-on: "2023-12-31" 
  98f76d54-3bc1-50cd-9a07-b28a3c6d8e4f: #should be present but its not enabled
    enabled: false 
    reason: "Another test reason"
`

	var config Config
	err = yaml.Unmarshal([]byte(identitiesYAML), &config)
	if err != nil {
		t.Fatalf("Failed to parse identities YAML: %v", err)
	}

	// Run the filter function
	currentTime, _ := time.Parse("2006-01-02", "2023-06-01") // Set a date before expiration
	filteredSarif := filterIdentities(&sarif, config.Identities, currentTime)

	// Check the results
	if len(filteredSarif.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(filteredSarif.Runs))
	}

	// Update the expected behavior
	if len(filteredSarif.Runs[0].Results) != 2 {
		t.Fatalf("Expected 2 result after filtering, got %d", len(filteredSarif.Runs[0].Results))
	}
}

func TestFilterIdentitiesNoMatches(t *testing.T) {
	// Test SARIF data with no matching identities (keep the existing SARIF JSON)
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Test Tool",
						"version": "1.0"
					}
				},
				"results": [
					{
						"ruleId": "TEST001",
						"message": {
							"text": "Test result 1"
						},
						"fingerprints": {
							"identity": "11111111-1111-1111-1111-111111111111"
						}
					},
					{
						"ruleId": "TEST002",
						"message": {
							"text": "Test result 2"
						},
						"fingerprints": {
							"identity": "22222222-2222-2222-2222-222222222222"
						}
					}
				]
			}
		]
	}`

	var sarif Sarif
	err := json.Unmarshal([]byte(sarifJSON), &sarif)
	if err != nil {
		t.Fatalf("Failed to unmarshal test SARIF data: %v", err)
	}

	// New Identity file content
	identitiesYAML := `
identities:
  33333333-3333-3333-3333-333333333333:
    enabled: true
    reason: "Test reason"
  44444444-4444-4444-4444-444444444444:
    enabled: false
    reason: "Another test reason"
    expires-on: "2023-12-31"
`

	var config Config
	err = yaml.Unmarshal([]byte(identitiesYAML), &config)
	if err != nil {
		t.Fatalf("Failed to parse identities YAML: %v", err)
	}

	// Run the filter function
	currentTime := time.Now()
	filteredSarif := filterIdentities(&sarif, config.Identities, currentTime)

	// Check the results
	if !reflect.DeepEqual(sarif, *filteredSarif) {
		t.Errorf("Expected no changes in SARIF data, but got differences")
	}
}

func TestParseIdentities(t *testing.T) {
	yamlStr := `
identities:
  84e70d75-2ac2-40ab-8a06-a17a2b5be9f5:
    enabled: true
    reason: "Test reason 1"
    expires-on: "2023-12-31"
  98f76d54-3bc1-50cd-9a07-b28a3c6d8e4f:
    enabled: false
    reason: "Test reason 2"
  11111111-1111-1111-1111-111111111111:
    enabled: true
`

	expected := Config{
		Identities: map[string]Identity{
			"84e70d75-2ac2-40ab-8a06-a17a2b5be9f5": {
				Enabled:   true,
				Reason:    "Test reason 1",
				ExpiresOn: "2023-12-31",
			},
			"98f76d54-3bc1-50cd-9a07-b28a3c6d8e4f": {
				Enabled: false,
				Reason:  "Test reason 2",
			},
			"11111111-1111-1111-1111-111111111111": {
				Enabled: true,
			},
		},
	}

	var config Config
	err := yaml.Unmarshal([]byte(yamlStr), &config)
	if err != nil {
		t.Fatalf("Failed to parse identities YAML: %v", err)
	}

	if !reflect.DeepEqual(config, expected) {
		t.Errorf("Parsed identities do not match expected. Got %+v, want %+v", config, expected)
	}
}

func TestFilterIdentitiesWithExpiration(t *testing.T) {
	sarifJSON := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Test Tool",
						"version": "1.0"
					}
				},
				"results": [
					{
						"ruleId": "TEST001",
						"message": {
							"text": "Test result 1"
						},
						"fingerprints": {
							"identity": "expired-id"
						}
					},
					{
						"ruleId": "TEST002",
						"message": {
							"text": "Test result 2"
						},
						"fingerprints": {
							"identity": "not-expired-id"
						}
					},
					{
						"ruleId": "TEST003",
						"message": {
							"text": "Test result 3"
						},
						"fingerprints": {
							"identity": "no-expiration-id"
						}
					}
				]
			}
		]
	}`

	var sarif Sarif
	err := json.Unmarshal([]byte(sarifJSON), &sarif)
	if err != nil {
		t.Fatalf("Failed to unmarshal test SARIF data: %v", err)
	}

	identitiesYAML := `
identities:
  expired-id:
    enabled: true
    reason: "Expired identity"
    expires-on: "2023-01-01"
  not-expired-id:
    enabled: true
    reason: "Not expired identity"
    expires-on: "2025-01-01"
  no-expiration-id:
    enabled: true
    reason: "No expiration date"
`

	var config Config
	err = yaml.Unmarshal([]byte(identitiesYAML), &config)
	if err != nil {
		t.Fatalf("Failed to parse identities YAML: %v", err)
	}

	// Set a fixed current time for testing
	currentTime, _ := time.Parse("2006-01-02", "2024-01-01")

	filteredSarif := filterIdentities(&sarif, config.Identities, currentTime)

	// Check the results
	if len(filteredSarif.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(filteredSarif.Runs))
	}

	if len(filteredSarif.Runs[0].Results) != 2 {
		t.Fatalf("Expected 2 result after filtering, got %d", len(filteredSarif.Runs[0].Results))
	}

	expectedIdentity := "not-expired-id"
	if filteredSarif.Runs[0].Results[0].Fingerprints["identity"] != expectedIdentity {
		t.Errorf("Expected remaining result to have identity %s, got %s",
			expectedIdentity, filteredSarif.Runs[0].Results[0].Fingerprints["identity"])
	}
}
