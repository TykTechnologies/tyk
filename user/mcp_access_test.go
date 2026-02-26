package user_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

func TestAccessControlRules_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		rules    user.AccessControlRules
		expected bool
	}{
		{
			name:     "zero value is empty",
			rules:    user.AccessControlRules{},
			expected: true,
		},
		{
			name:     "nil slices is empty",
			rules:    user.AccessControlRules{Allowed: nil, Blocked: nil},
			expected: true,
		},
		{
			name:     "allowed list makes it non-empty",
			rules:    user.AccessControlRules{Allowed: []string{"tools/call"}},
			expected: false,
		},
		{
			name:     "blocked list makes it non-empty",
			rules:    user.AccessControlRules{Blocked: []string{"tools/call"}},
			expected: false,
		},
		{
			name:     "both lists non-empty",
			rules:    user.AccessControlRules{Allowed: []string{"a"}, Blocked: []string{"b"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.rules.IsEmpty())
			assert.Equal(t, tt.expected, tt.rules.IsZero())
		})
	}
}

func TestMCPAccessRights_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		rights   user.MCPAccessRights
		expected bool
	}{
		{
			name:     "zero value is empty",
			rights:   user.MCPAccessRights{},
			expected: true,
		},
		{
			name: "tools rule makes it non-empty",
			rights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Allowed: []string{"weather"}},
			},
			expected: false,
		},
		{
			name: "resources rule makes it non-empty",
			rights: user.MCPAccessRights{
				Resources: user.AccessControlRules{Blocked: []string{"secrets"}},
			},
			expected: false,
		},
		{
			name: "prompts rule makes it non-empty",
			rights: user.MCPAccessRights{
				Prompts: user.AccessControlRules{Allowed: []string{"summarize"}},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.rights.IsEmpty())
			assert.Equal(t, tt.expected, tt.rights.IsZero())
		})
	}
}

func TestAccessControlRules_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		input user.AccessControlRules
	}{
		{
			name:  "empty rules",
			input: user.AccessControlRules{},
		},
		{
			name:  "allowed only",
			input: user.AccessControlRules{Allowed: []string{"tools/call", "ping"}},
		},
		{
			name:  "blocked only",
			input: user.AccessControlRules{Blocked: []string{"admin/.*"}},
		},
		{
			name:  "both allowed and blocked",
			input: user.AccessControlRules{Allowed: []string{"a", "b"}, Blocked: []string{"c"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			require.NoError(t, err)

			var out user.AccessControlRules
			require.NoError(t, json.Unmarshal(data, &out))
			assert.Equal(t, tt.input, out)
		})
	}
}

func TestJSONRPCMethodLimit_JSONRoundtrip(t *testing.T) {
	input := user.JSONRPCMethodLimit{
		Name:  "tools/call",
		Limit: user.RateLimit{Rate: 100, Per: 60},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var out user.JSONRPCMethodLimit
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, input, out)
}

func TestMCPPrimitiveLimit_JSONRoundtrip(t *testing.T) {
	input := user.MCPPrimitiveLimit{
		Type:  "tool",
		Name:  "get-weather",
		Limit: user.RateLimit{Rate: 50, Per: 30},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var out user.MCPPrimitiveLimit
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, input, out)
}

func TestAccessDefinition_MCPFields_JSONRoundtrip(t *testing.T) {
	input := user.AccessDefinition{
		APIID:   "test-api",
		APIName: "Test",
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: user.RateLimit{Rate: 10, Per: 1}},
		},
		JSONRPCMethodsAccessRights: user.AccessControlRules{
			Allowed: []string{"tools/call"},
			Blocked: []string{"admin/.*"},
		},
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: "tool", Name: "weather", Limit: user.RateLimit{Rate: 5, Per: 1}},
		},
		MCPAccessRights: user.MCPAccessRights{
			Tools:     user.AccessControlRules{Allowed: []string{"weather"}},
			Resources: user.AccessControlRules{Blocked: []string{"private/.*"}},
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var out user.AccessDefinition
	require.NoError(t, json.Unmarshal(data, &out))
	assert.Equal(t, input.JSONRPCMethods, out.JSONRPCMethods)
	assert.Equal(t, input.JSONRPCMethodsAccessRights, out.JSONRPCMethodsAccessRights)
	assert.Equal(t, input.MCPPrimitives, out.MCPPrimitives)
	assert.Equal(t, input.MCPAccessRights, out.MCPAccessRights)
}

func TestMCPPrimitiveLimit_Validate(t *testing.T) {
	tests := []struct {
		name      string
		primitive user.MCPPrimitiveLimit
		expectErr bool
	}{
		{"tool is valid", user.MCPPrimitiveLimit{Type: "tool", Name: "weather"}, false},
		{"resource is valid", user.MCPPrimitiveLimit{Type: "resource", Name: "file://data"}, false},
		{"prompt is valid", user.MCPPrimitiveLimit{Type: "prompt", Name: "summarize"}, false},
		{"empty type is invalid", user.MCPPrimitiveLimit{Type: "", Name: "something"}, true},
		{"unknown type is invalid", user.MCPPrimitiveLimit{Type: "unknown", Name: "something"}, true},
		{"uppercase type is invalid", user.MCPPrimitiveLimit{Type: "Tool", Name: "something"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.primitive.Validate()
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid MCP primitive type")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAccessDefinition_ZeroMCPFields_OmittedFromJSON(t *testing.T) {
	input := user.AccessDefinition{
		APIID:   "test-api",
		APIName: "Test",
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	// Zero-value slice and struct fields should be absent from JSON.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.NotContains(t, raw, "json_rpc_methods")
	assert.NotContains(t, raw, "mcp_primitives")
}
