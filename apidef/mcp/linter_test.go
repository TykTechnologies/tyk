package mcp

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func TestXTykAPIGateway_Lint_MCP(t *testing.T) {
	oasObj := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "MCP Linter Test API",
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		},
	}

	settings := oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "mcp-comprehensive-test",
			State: oas.State{
				Active: true,
			},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/mcp-test/",
			},
		},
		Upstream: oas.Upstream{
			URL: "http://upstream.test",
		},
		Middleware: &oas.Middleware{
			Global: &oas.Global{
				CORS: &oas.CORS{
					Enabled: true,
				},
			},
			McpTools: map[string]*oas.MCPPrimitive{
				"test-tool-1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
				"test-tool-2": {
					Operation: oas.Operation{
						Block: &oas.Allowance{
							Enabled: true,
						},
					},
				},
			},
			McpResources: map[string]*oas.MCPPrimitive{
				"test-resource-1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
				"test-resource-2": {
					Operation: oas.Operation{
						TransformRequestHeaders: &oas.TransformHeaders{
							Enabled: true,
							Remove:  []string{"X-Custom"},
						},
					},
				},
			},
			McpPrompts: map[string]*oas.MCPPrimitive{
				"test-prompt-1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
				"test-prompt-2": {
					Operation: oas.Operation{
						ValidateRequest: &oas.ValidateRequest{
							Enabled: true,
						},
					},
				},
			},
		},
	}

	oasObj.SetTykExtension(&settings)
	definition, err := oasObj.MarshalJSON()
	require.NoError(t, err)

	err = ValidateMCPObject(definition, "3.0.3")
	require.NoError(t, err, "MCP schema should accept middleware applied to all MCP primitive types (tools, resources, prompts)")
}
