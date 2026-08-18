package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

func TestFilterDiscoveryBody(t *testing.T) {
	t.Parallel()
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"demo","version":"1"},"unknown":true},"ttlMs":5000,"cacheScope":"public","supportedVersions":["2024-11-05","2026-07-28","2026-07-28","2025-03-26"],"capabilities":{"tools":{"listChanged":false},"resources":{"listChanged":false},"sampling":{},"experimental":{"custom":true}},"instructions":"preserve","extension":{"x":1}}}`)
	credentialRules := []user.AccessControlRules{{Blocked: []string{MethodToolsCall}}}

	filtered, changed, credentialSpecific := FilterDiscoveryBody(body, nil, credentialRules)
	require.True(t, changed)
	require.True(t, credentialSpecific)

	var response map[string]any
	require.NoError(t, json.Unmarshal(filtered, &response))
	result := response["result"].(map[string]any)
	assert.Equal(t, []any{"2026-07-28", "2025-03-26"}, result["supportedVersions"])
	assert.Equal(t, "private", result["cacheScope"])
	assert.Equal(t, float64(0), result["ttlMs"])
	capabilities := result["capabilities"].(map[string]any)
	assert.NotContains(t, capabilities, "tools")
	assert.Contains(t, capabilities, "resources")
	assert.Contains(t, capabilities, "sampling", "an advertised empty capability must be retained")
	assert.Contains(t, capabilities, "experimental")
	assert.Equal(t, "preserve", result["instructions"])
	assert.NotNil(t, result["extension"])
	assert.NotNil(t, result["_meta"])
}

func TestFilterDiscoveryBody_GlobalVersionEditRemainsPublic(t *testing.T) {
	t.Parallel()
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","cacheScope":"public","ttlMs":1000,"supportedVersions":["2025-03-26","2024-11-05"],"capabilities":{"tools":{}}}}`)
	filtered, changed, credentialSpecific := FilterDiscoveryBody(body, nil, nil)
	require.True(t, changed)
	assert.False(t, credentialSpecific)
	assert.Contains(t, string(filtered), `"cacheScope":"public"`)
	assert.Contains(t, string(filtered), `"ttlMs":1000`)
	assert.NotContains(t, string(filtered), "2024-11-05")
}

func TestFilterDiscoveryBody_UnchangedPreservesOriginalBytes(t *testing.T) {
	t.Parallel()
	body := []byte("{ \"jsonrpc\": \"2.0\", \"result\": {\"supportedVersions\":[\"2026-07-28\",\"2025-11-25\",\"2025-06-18\",\"2025-03-26\"],\"capabilities\":{\"sampling\":{}}}, \"id\": 1 }")
	filtered, changed, credentialSpecific := FilterDiscoveryBody(body, nil, nil)
	assert.False(t, changed)
	assert.False(t, credentialSpecific)
	assert.Nil(t, filtered)
}
