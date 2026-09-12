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

	filtered, changed, credentialSpecific, err := FilterDiscoveryBody(body, nil, credentialRules)
	require.NoError(t, err)
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
	filtered, changed, credentialSpecific, err := FilterDiscoveryBody(body, nil, nil)
	require.NoError(t, err)
	require.True(t, changed)
	assert.False(t, credentialSpecific)
	assert.Contains(t, string(filtered), `"cacheScope":"public"`)
	assert.Contains(t, string(filtered), `"ttlMs":1000`)
	assert.NotContains(t, string(filtered), "2024-11-05")
}

func TestFilterDiscoveryBody_UnchangedPreservesOriginalBytes(t *testing.T) {
	t.Parallel()
	body := []byte("{ \"jsonrpc\": \"2.0\", \"result\": {\"supportedVersions\":[\"2026-07-28\",\"2025-11-25\",\"2025-06-18\",\"2025-03-26\"],\"capabilities\":{\"sampling\":{}}}, \"id\": 1 }")
	filtered, changed, credentialSpecific, err := FilterDiscoveryBody(body, nil, nil)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.False(t, credentialSpecific)
	assert.Nil(t, filtered)
}

func TestDiscoveryCredentialRulesAndEndpointSupport(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"extension":true,"result":{"resultType":"complete","supportedVersions":["2026-07-28","2025-03-26"],"capabilities":{"tools":{}},"instructions":"keep","_meta":{"unknown":true}}}`)
	filtered, changed, private, err := FilterDiscoveryBody(body, nil, []user.AccessControlRules{{Blocked: []string{"resources/read"}}}, legacyEndpoint{})
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, private, "applicable method rules are credential-dependent even without removals")
	var response map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(filtered, &response))
	require.Equal(t, "9007199254740993", string(response["id"]))
	require.Equal(t, "true", string(response["extension"]))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(response["result"], &result))
	require.JSONEq(t, `["2025-03-26"]`, string(result["supportedVersions"]))
	require.JSONEq(t, `{"tools":{}}`, string(result["capabilities"]))
	require.Equal(t, `"private"`, string(result["cacheScope"]))
	require.Equal(t, `0`, string(result["ttlMs"]))
	require.Equal(t, `"complete"`, string(result["resultType"]))
	require.JSONEq(t, `{"unknown":true}`, string(result["_meta"]))
}

func TestFilterDiscoveryBodyRejectsMalformedOwnedShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{"truncated", `{"jsonrpc":"2.0","id":1,"result":`},
		{"non object envelope", `[]`},
		{"trailing value", `{"jsonrpc":"2.0","id":1,"result":{}} {}`},
		{"missing jsonrpc", `{"id":1,"result":{}}`},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"result":{}}`},
		{"missing id", `{"jsonrpc":"2.0","result":{}}`},
		{"invalid id", `{"jsonrpc":"2.0","id":true,"result":{}}`},
		{"result and error", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1}}`},
		{"neither result nor error", `{"jsonrpc":"2.0","id":1}`},
		{"null result", `{"jsonrpc":"2.0","id":1,"result":null}`},
		{"array result", `{"jsonrpc":"2.0","id":1,"result":[]}`},
		{"missing versions", `{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}`},
		{"null versions", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":null,"capabilities":{}}}`},
		{"scalar versions", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":1,"capabilities":{}}}`},
		{"mixed versions", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28",1],"capabilities":{}}}`},
		{"missing capabilities", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[]}}`},
		{"null capabilities", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[],"capabilities":null}}`},
		{"array capabilities", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[],"capabilities":[]}}`},
		{"duplicate result", `{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`},
		{"duplicate versions", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[],"supportedVersions":[],"capabilities":{}}}`},
		{"duplicate capabilities", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[],"capabilities":{},"capabilities":{}}}`},
		{"duplicate owned capability", `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[],"capabilities":{"tools":{},"tools":{}}}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filtered, changed, private, err := FilterDiscoveryBody([]byte(test.body), nil, nil)
			require.Nil(t, filtered)
			require.False(t, changed)
			require.False(t, private)
			require.Error(t, err)
			require.True(t, IsInvalidDiscoveryError(err), err)
		})
	}
}

func TestFilterDiscoveryBodyPreservesValidErrorsEmptyValuesAndUnknownFields(t *testing.T) {
	t.Parallel()
	t.Run("upstream error", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","id":"request","error":{"code":-32001,"message":"upstream","extension":{"secret":"opaque"}},"unknown":true}`)
		filtered, changed, private, err := FilterDiscoveryBody(body, nil, nil)
		require.NoError(t, err)
		require.Nil(t, filtered)
		require.False(t, changed)
		require.False(t, private)
	})
	t.Run("empty values", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","id":0,"result":{"supportedVersions":[],"capabilities":{},"unknown":{"kept":true}}}`)
		filtered, changed, private, err := FilterDiscoveryBody(body, nil, nil)
		require.NoError(t, err)
		require.Nil(t, filtered)
		require.False(t, changed)
		require.False(t, private)
	})
}

func TestJSONRPCResponseIDStatusPreservesExactIdentity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		body     string
		expected any
		match    bool
	}{
		{`{"id":9007199254740992}`, json.Number("9007199254740992"), true},
		{`{"id":9007199254740993}`, json.Number("9007199254740993"), true},
		{`{"id":9007199254740993}`, json.Number("9007199254740992"), false},
		{`{"id":"9007199254740993"}`, "9007199254740993", true},
	} {
		present, match, err := JSONRPCResponseIDStatus([]byte(test.body), test.expected)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, test.match, match)
	}
}
