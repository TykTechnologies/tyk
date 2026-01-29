package apidef

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadedAPIInfo_JSONSerialization(t *testing.T) {
	info := LoadedAPIInfo{APIID: "api-123"}

	data, err := json.Marshal(info)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"api_id":"api-123"}`, string(data))

	var decoded LoadedAPIInfo
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "api-123", decoded.APIID)
}

func TestLoadedPolicyInfo_JSONSerialization(t *testing.T) {
	info := LoadedPolicyInfo{PolicyID: "pol-456"}

	data, err := json.Marshal(info)
	assert.NoError(t, err)
	assert.JSONEq(t, `{"policy_id":"pol-456"}`, string(data))

	var decoded LoadedPolicyInfo
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "pol-456", decoded.PolicyID)
}

func TestGWStats_WithLoadedResources_JSONSerialization(t *testing.T) {
	stats := GWStats{
		APIsCount:     2,
		PoliciesCount: 1,
		LoadedAPIs: []LoadedAPIInfo{
			{APIID: "api-1"},
			{APIID: "api-2"},
		},
		LoadedPolicies: []LoadedPolicyInfo{
			{PolicyID: "pol-1"},
		},
	}

	data, err := json.Marshal(stats)
	assert.NoError(t, err)

	expected := `{
		"apis_count": 2,
		"policies_count": 1,
		"loaded_apis": [{"api_id": "api-1"}, {"api_id": "api-2"}],
		"loaded_policies": [{"policy_id": "pol-1"}]
	}`
	assert.JSONEq(t, expected, string(data))
}

func TestGWStats_EmptyLoadedResources_OmitsFields(t *testing.T) {
	stats := GWStats{
		APIsCount:     0,
		PoliciesCount: 0,
	}

	data, err := json.Marshal(stats)
	assert.NoError(t, err)

	// Should not contain loaded_apis or loaded_policies when nil
	assert.NotContains(t, string(data), "loaded_apis")
	assert.NotContains(t, string(data), "loaded_policies")
}
