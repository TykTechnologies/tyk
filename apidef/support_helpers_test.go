package apidef

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SW-REQ-019
// SW-REQ-019:nominal:nominal
// SW-REQ-019:boundary:boundary
// MCDC SYS-REQ-104: api_definition_support_requested=T, api_definition_support_shape_preserved=T => TRUE
func TestHealthCheckResponseJSONShape(t *testing.T) {
	t.Parallel()

	response := HealthCheckResponse{
		Status:      Pass,
		Version:     "v1",
		Output:      "ok",
		Description: "ready",
		Details: map[string]HealthCheckItem{
			"redis": {
				Status:        Warn,
				Output:        "slow",
				ComponentType: string(Datastore),
				ComponentID:   "redis-main",
				Time:          "2026-06-20T00:00:00Z",
			},
		},
	}

	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"status":"pass",
		"version":"v1",
		"output":"ok",
		"description":"ready",
		"details":{
			"redis":{
				"status":"warn",
				"output":"slow",
				"componentType":"datastore",
				"componentId":"redis-main",
				"time":"2026-06-20T00:00:00Z"
			}
		}
	}`, string(encoded))

	encoded, err = json.Marshal(HealthCheckResponse{Status: Fail})
	require.NoError(t, err)
	assert.JSONEq(t, `{"status":"fail"}`, string(encoded))
	assert.Equal(t, "component", string(Component))
	assert.Equal(t, "system", string(System))
}

// Verifies: SW-REQ-020
// SW-REQ-020:nominal:nominal
// SW-REQ-020:boundary:boundary
// SW-REQ-020:error_handling:negative
func TestHostList(t *testing.T) {
	t.Parallel()

	hosts := NewHostList()
	require.NotNil(t, hosts)
	assert.Empty(t, hosts.All())
	assert.Equal(t, 0, hosts.Len())

	hosts.Set([]string{"one", "two"})
	assert.Equal(t, []string{"one", "two"}, hosts.All())
	assert.Equal(t, 2, hosts.Len())

	host, err := hosts.GetIndex(0)
	require.NoError(t, err)
	assert.Equal(t, "one", host)

	host, err = hosts.GetIndex(1)
	require.NoError(t, err)
	assert.Equal(t, "two", host)

	host, err = hosts.GetIndex(-1)
	assert.Empty(t, host)
	require.EqualError(t, err, "index must be positive int")

	host, err = hosts.GetIndex(2)
	assert.Empty(t, host)
	require.EqualError(t, err, "index out of range")

	fromList := NewHostListFromList([]string{"api.example"})
	assert.Equal(t, 1, fromList.Len())
	host, err = fromList.GetIndex(0)
	require.NoError(t, err)
	assert.Equal(t, "api.example", host)
}

// Verifies: SW-REQ-021
// SW-REQ-021:nominal:nominal
// SW-REQ-021:boundary:boundary
func TestErrorOverrideCompiledTemplates(t *testing.T) {
	t.Parallel()

	override := &ErrorOverride{}
	assert.False(t, override.HasCompiledTemplate())
	assert.Nil(t, override.GetCompiledTemplate(true))
	assert.Nil(t, override.GetCompiledTemplate(false))

	textTemplate := struct{ name string }{"text"}
	htmlTemplate := struct{ name string }{"html"}
	override.SetCompiledTemplates(textTemplate, htmlTemplate)

	assert.True(t, override.HasCompiledTemplate())
	assert.Equal(t, textTemplate, override.GetCompiledTemplate(true))
	assert.Equal(t, htmlTemplate, override.GetCompiledTemplate(false))
}

// Verifies: SW-REQ-021
// SW-REQ-021:nominal:nominal
// SW-REQ-021:boundary:boundary
// SW-REQ-021:error_handling:negative
func TestErrorMatcherCompile(t *testing.T) {
	t.Parallel()

	matcher := &ErrorMatcher{MessagePattern: `^upstream \d+$`}
	require.NoError(t, matcher.Compile())
	require.NotNil(t, matcher.CompiledPattern)
	assert.True(t, matcher.CompiledPattern.MatchString("upstream 42"))
	assert.False(t, matcher.CompiledPattern.MatchString("downstream 42"))

	compiled := matcher.CompiledPattern
	require.NoError(t, matcher.Compile())
	assert.Same(t, compiled, matcher.CompiledPattern)

	empty := &ErrorMatcher{}
	require.NoError(t, empty.Compile())
	assert.Nil(t, empty.CompiledPattern)

	invalid := &ErrorMatcher{MessagePattern: `(`}
	err := invalid.Compile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid regex pattern "("`)
	assert.Nil(t, invalid.CompiledPattern)
}
