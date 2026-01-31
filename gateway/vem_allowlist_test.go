package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// TestHasOperationAllowEnabled tests detection of allow middleware in operations.
// Operations are JSON-RPC method-level configurations (tools/call, resources/read, etc.)
func TestHasOperationAllowEnabled(t *testing.T) {
	tests := []struct {
		name       string
		operations oas.Operations
		expected   bool
	}{
		{
			name: "no operations",
			operations: oas.Operations{},
			expected: false,
		},
		{
			name: "operation without allow",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{},
			},
			expected: false,
		},
		{
			name: "operation with allow disabled",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: false},
				},
			},
			expected: false,
		},
		{
			name: "operation with allow enabled",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			expected: true,
		},
		{
			name: "multiple operations, one with allow",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
				"json-rpc-method:tools/list": &oas.Operation{},
			},
			expected: true,
		},
		{
			name: "multiple operations, none with allow",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{},
				"json-rpc-method:tools/list": &oas.Operation{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasOperationAllowEnabled(tt.operations)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHasPrimitiveAllowEnabled tests detection of allow middleware in primitives.
// Primitives are MCP-specific resources (tools, resources, prompts).
func TestHasPrimitiveAllowEnabled(t *testing.T) {
	tests := []struct {
		name       string
		primitives oas.MCPPrimitives
		expected   bool
	}{
		{
			name:       "no primitives",
			primitives: oas.MCPPrimitives{},
			expected:   false,
		},
		{
			name: "primitive without allow",
			primitives: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{},
			},
			expected: false,
		},
		{
			name: "primitive with allow disabled",
			primitives: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: false},
					},
				},
			},
			expected: false,
		},
		{
			name: "primitive with allow enabled",
			primitives: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: true},
					},
				},
			},
			expected: true,
		},
		{
			name: "multiple primitives, one with allow",
			primitives: oas.MCPPrimitives{
				"tool-A": &oas.MCPPrimitive{
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: true},
					},
				},
				"tool-B": &oas.MCPPrimitive{},
			},
			expected: true,
		},
		{
			name: "multiple primitives, none with allow",
			primitives: oas.MCPPrimitives{
				"tool-A": &oas.MCPPrimitive{},
				"tool-B": &oas.MCPPrimitive{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasPrimitiveAllowEnabled(tt.primitives)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHasAllowListEnabled tests combined detection of allow middleware at both levels.
// This validates the unified allowlist logic that works for JSON-RPC operations and MCP primitives.
func TestHasAllowListEnabled(t *testing.T) {
	tests := []struct {
		name       string
		operations oas.Operations
		categories []PrimitiveCategory
		expected   bool
	}{
		{
			name:       "no operations or primitives",
			operations: oas.Operations{},
			categories: []PrimitiveCategory{},
			expected:   false,
		},
		{
			name: "operation with allow, no primitives",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			categories: []PrimitiveCategory{},
			expected:   true,
		},
		{
			name:       "primitive with allow, no operations",
			operations: oas.Operations{},
			categories: []PrimitiveCategory{
				{
					Prefix:   "/mcp-tool:",
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool-A": &oas.MCPPrimitive{
							Operation: oas.Operation{
								Allow: &oas.Allowance{Enabled: true},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "both operation and primitive with allow",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			categories: []PrimitiveCategory{
				{
					Prefix:   "/mcp-tool:",
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool-A": &oas.MCPPrimitive{
							Operation: oas.Operation{
								Allow: &oas.Allowance{Enabled: true},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "neither operation nor primitive has allow",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{},
			},
			categories: []PrimitiveCategory{
				{
					Prefix:   "/mcp-tool:",
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool-A": &oas.MCPPrimitive{},
					},
				},
			},
			expected: false,
		},
		{
			name: "operation has allow but disabled",
			operations: oas.Operations{
				"json-rpc-method:tools/call": &oas.Operation{
					Allow: &oas.Allowance{Enabled: false},
				},
			},
			categories: []PrimitiveCategory{},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAllowListEnabled(tt.operations, tt.categories)
			assert.Equal(t, tt.expected, result)
		})
	}
}
