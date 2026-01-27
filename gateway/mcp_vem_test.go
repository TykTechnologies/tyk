package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/regexp"
)

func Test_sanitizeMCPName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple name",
			input:    "get-weather",
			expected: "get-weather",
		},
		{
			name:     "resource pattern with file protocol",
			input:    "file:///repo/*",
			expected: "file__repo_*", // file:// -> file_ and then /repo/* -> _repo_*
		},
		{
			name:     "resource pattern with http protocol",
			input:    "http://example.com/api",
			expected: "http_example.com_api",
		},
		{
			name:     "name with colons",
			input:    "my:tool:name",
			expected: "my_tool_name",
		},
		{
			name:     "name with slashes",
			input:    "path/to/resource",
			expected: "path_to_resource",
		},
		{
			name:     "complex pattern",
			input:    "https://api.example.com:8080/v1/resources/*",
			expected: "https_api.example.com_8080_v1_resources_*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mcp.SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_generateMCPVEMs_NonMCPAPI(t *testing.T) {
	// Create a non-MCP API spec
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: "", // Not MCP
			JsonRpcVersion:      "",
		},
	}

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Nil(t, specs, "should return nil for non-MCP API")
}

func Test_generateMCPVEMs_NoMiddleware(t *testing.T) {
	// Create an MCP API spec without OAS middleware
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Nil(t, specs, "should return nil when no middleware is configured")
}

func Test_generateMCPVEMs_WithTools(t *testing.T) {
	// Create an MCP API spec with tools
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"get-weather": {
					Allow: &oas.Allowance{Enabled: true},
				},
				"stock-prices": {
					RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 100},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 2)
	for _, spec := range specs {
		assert.Equal(t, MCPPrimitive, spec.Status)
		assert.Equal(t, "tool", spec.MCPPrimitiveMeta.Type)
		assert.Equal(t, "POST", spec.MCPPrimitiveMeta.Method)
	}

	// Check MCPPrimitives map
	assert.NotNil(t, apiSpec.MCPPrimitives)
	assert.Contains(t, apiSpec.MCPPrimitives, "tool:get-weather")
	assert.Contains(t, apiSpec.MCPPrimitives, "tool:stock-prices")
	assert.Equal(t, "/mcp-tool:get-weather", apiSpec.MCPPrimitives["tool:get-weather"])
	assert.Equal(t, "/mcp-tool:stock-prices", apiSpec.MCPPrimitives["tool:stock-prices"])
}

func Test_generateMCPVEMs_WithResources(t *testing.T) {
	// Create an MCP API spec with resources
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpResources: map[string]*oas.Operation{
				"file:///repo/*": {
					Allow: &oas.Allowance{Enabled: true},
				},
				"internal_policy": {
					RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 500},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 2)
	for _, spec := range specs {
		assert.Equal(t, MCPPrimitive, spec.Status)
		assert.Equal(t, "resource", spec.MCPPrimitiveMeta.Type)
		assert.Equal(t, "POST", spec.MCPPrimitiveMeta.Method)
	}

	// Check MCPPrimitives map
	assert.NotNil(t, apiSpec.MCPPrimitives)
	assert.Contains(t, apiSpec.MCPPrimitives, "resource:file:///repo/*")
	assert.Contains(t, apiSpec.MCPPrimitives, "resource:internal_policy")
	assert.Equal(t, "/mcp-resource:file__repo_*", apiSpec.MCPPrimitives["resource:file:///repo/*"])
	assert.Equal(t, "/mcp-resource:internal_policy", apiSpec.MCPPrimitives["resource:internal_policy"])
}

func Test_generateMCPVEMs_WithPrompts(t *testing.T) {
	// Create an MCP API spec with prompts
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpPrompts: map[string]*oas.Operation{
				"code-review": {
					Allow: &oas.Allowance{Enabled: true},
				},
				"summarize-document": {
					RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 50},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 2)
	for _, spec := range specs {
		assert.Equal(t, MCPPrimitive, spec.Status)
		assert.Equal(t, "prompt", spec.MCPPrimitiveMeta.Type)
		assert.Equal(t, "POST", spec.MCPPrimitiveMeta.Method)
	}

	// Check MCPPrimitives map
	assert.NotNil(t, apiSpec.MCPPrimitives)
	assert.Contains(t, apiSpec.MCPPrimitives, "prompt:code-review")
	assert.Contains(t, apiSpec.MCPPrimitives, "prompt:summarize-document")
	assert.Equal(t, "/mcp-prompt:code-review", apiSpec.MCPPrimitives["prompt:code-review"])
	assert.Equal(t, "/mcp-prompt:summarize-document", apiSpec.MCPPrimitives["prompt:summarize-document"])
}

func Test_generateMCPVEMs_WithAllPrimitives(t *testing.T) {
	// Create an MCP API spec with all primitive types
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"get-weather": {Allow: &oas.Allowance{Enabled: true}},
			},
			McpResources: map[string]*oas.Operation{
				"file:///repo/*": {Allow: &oas.Allowance{Enabled: true}},
			},
			McpPrompts: map[string]*oas.Operation{
				"code-review": {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 3)

	// Verify all primitive types are present
	typeCount := map[string]int{}
	for _, spec := range specs {
		typeCount[spec.MCPPrimitiveMeta.Type]++
	}
	assert.Equal(t, 1, typeCount["tool"])
	assert.Equal(t, 1, typeCount["resource"])
	assert.Equal(t, 1, typeCount["prompt"])

	// Check MCPPrimitives map has all entries
	assert.Len(t, apiSpec.MCPPrimitives, 3)
	assert.Contains(t, apiSpec.MCPPrimitives, "tool:get-weather")
	assert.Contains(t, apiSpec.MCPPrimitives, "resource:file:///repo/*")
	assert.Contains(t, apiSpec.MCPPrimitives, "prompt:code-review")
}

func Test_generateMCPVEMs_EmptyMCPSections(t *testing.T) {
	// Create an MCP API spec with empty MCP sections
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools:     map[string]*oas.Operation{},
			McpResources: map[string]*oas.Operation{},
			McpPrompts:   map[string]*oas.Operation{},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Empty(t, specs, "should return empty slice for empty MCP sections")
	assert.Empty(t, apiSpec.MCPPrimitives, "MCPPrimitives map should be empty")
}

func Test_buildMCPPrimitiveSpec(t *testing.T) {
	loader := APIDefinitionLoader{}
	op := &oas.Operation{
		Allow: &oas.Allowance{Enabled: true},
	}

	spec := loader.buildMCPPrimitiveSpec("test-tool", "tool", mcp.ToolPrefix, op, config.Config{})

	assert.Equal(t, MCPPrimitive, spec.Status)
	assert.Equal(t, "test-tool", spec.MCPPrimitiveMeta.Name)
	assert.Equal(t, "tool", spec.MCPPrimitiveMeta.Type)
	assert.Equal(t, "POST", spec.MCPPrimitiveMeta.Method)
	assert.Equal(t, op, spec.MCPPrimitiveMeta.Operation)
}

func Test_URLSpec_matchesMethod_MCPPrimitive(t *testing.T) {
	spec := URLSpec{
		Status: MCPPrimitive,
		MCPPrimitiveMeta: MCPPrimitiveMeta{
			Method: "POST",
		},
	}

	assert.True(t, spec.matchesMethod("POST"), "should match POST method")
	assert.False(t, spec.matchesMethod("GET"), "should not match GET method")
	assert.False(t, spec.matchesMethod("PUT"), "should not match PUT method")
}

func Test_URLSpec_modeSpecificSpec_MCPPrimitive(t *testing.T) {
	spec := URLSpec{
		Status: MCPPrimitive,
		MCPPrimitiveMeta: MCPPrimitiveMeta{
			Name: "test-tool",
			Type: "tool",
		},
	}

	result, ok := spec.modeSpecificSpec(MCPPrimitive)
	assert.True(t, ok)
	assert.NotNil(t, result)

	meta, isMeta := result.(*MCPPrimitiveMeta)
	require.True(t, isMeta)
	assert.Equal(t, "test-tool", meta.Name)
	assert.Equal(t, "tool", meta.Type)
}

func Test_ctxMCPRouting(t *testing.T) {
	t.Run("default is false", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/test", nil)
		assert.False(t, httpctx.IsMCPRouting(r))
	})

	t.Run("set to true", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/test", nil)
		httpctx.SetMCPRouting(r, true)
		assert.True(t, httpctx.IsMCPRouting(r))
	})

	t.Run("set to false explicitly", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/test", nil)
		httpctx.SetMCPRouting(r, true)
		httpctx.SetMCPRouting(r, false)
		assert.False(t, httpctx.IsMCPRouting(r))
	})
}

func Test_getURLStatus_MCPPrimitive(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}

	status := apiSpec.getURLStatus(MCPPrimitive)
	assert.Equal(t, StatusMCPPrimitive, status)
}

func Test_URLAllowedAndIgnored_MCPPrimitive_DirectAccess(t *testing.T) {
	// Create an API spec
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
	}

	// Create RxPaths with MCPPrimitive entry
	rxPaths := []URLSpec{
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "get-weather",
				Type:   "tool",
				Method: "POST",
			},
		},
	}
	// Set up the regex to match the path
	rxPaths[0].spec = mustCompileRegex("/mcp-tool:get-weather")

	// Create request without MCP routing context
	r := httptest.NewRequest("POST", "/mcp-tool:get-weather", nil)

	// Execute
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)

	// Assert: Direct access should be blocked
	assert.Equal(t, EndPointNotAllowed, status, "direct access to MCP primitive should be blocked")
}

func Test_URLAllowedAndIgnored_MCPPrimitive_MCPRouting(t *testing.T) {
	// Create an API spec
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
	}

	// Create RxPaths with MCPPrimitive entry
	rxPaths := []URLSpec{
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "get-weather",
				Type:   "tool",
				Method: "POST",
			},
		},
	}
	// Set up the regex to match the path
	rxPaths[0].spec = mustCompileRegex("/mcp-tool:get-weather")

	// Create request with MCP routing context
	r := httptest.NewRequest("POST", "/mcp-tool:get-weather", nil)
	httpctx.SetMCPRouting(r, true)

	// Execute
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)

	// Assert: MCP routed access should NOT return EndPointNotAllowed
	// (it may return a different status depending on whitelist configuration)
	assert.NotEqual(t, EndPointNotAllowed, status, "MCP routed access should not be blocked")
}

func Test_URLAllowedAndIgnored_MCPPrimitive_WrongMethod(t *testing.T) {
	// Create an API spec
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
	}

	// Create RxPaths with MCPPrimitive entry (POST method)
	rxPaths := []URLSpec{
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "get-weather",
				Type:   "tool",
				Method: "POST",
			},
		},
	}
	// Set up the regex to match the path
	rxPaths[0].spec = mustCompileRegex("/mcp-tool:get-weather")

	// Create GET request without MCP routing context
	r := httptest.NewRequest("GET", "/mcp-tool:get-weather", nil)

	// Execute
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)

	// Assert: GET request should not trigger the MCPPrimitive block (method doesn't match)
	// This tests that the method check is working correctly
	assert.NotEqual(t, EndPointNotAllowed, status, "GET request should not be blocked by MCPPrimitive check (wrong method)")
}

func Test_APISpec_Unload_ClearsMCPPrimitives(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
		MCPPrimitives: map[string]string{
			"tool:get-weather": "/mcp-tool:get-weather",
		},
	}

	apiSpec.Unload()

	assert.Nil(t, apiSpec.MCPPrimitives, "MCPPrimitives should be nil after Unload")
}

// mustCompileRegex is a helper to compile regex for tests
func mustCompileRegex(pattern string) *regexp.Regexp {
	r, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return r
}

// === EDGE CASE TESTS ===

func Test_sanitizeMCPName_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "a",
		},
		{
			name:     "name with spaces",
			input:    "my tool name",
			expected: "my tool name", // spaces are preserved
		},
		{
			name:     "name with dots",
			input:    "api.example.com",
			expected: "api.example.com", // dots are preserved
		},
		{
			name:     "name with hyphens and underscores",
			input:    "my-tool_name",
			expected: "my-tool_name", // hyphens and underscores preserved
		},
		{
			name:     "multiple consecutive slashes",
			input:    "path///to///resource",
			expected: "path___to___resource",
		},
		{
			name:     "multiple colons",
			input:    "a:b:c:d",
			expected: "a_b_c_d",
		},
		{
			name:     "only special characters",
			input:    ":///::",
			expected: "____",
		},
		{
			name:     "unicode characters",
			input:    "工具-天气",
			expected: "工具-天气", // unicode preserved
		},
		{
			name:     "regex special characters",
			input:    "tool[0-9]+",
			expected: "tool[0-9]+", // regex chars preserved (may need escaping in regex)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mcp.SanitizeName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_generateMCPVEMs_NilOperation(t *testing.T) {
	// Create an MCP API spec with nil Operation values
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"nil-tool": nil, // nil Operation
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	// Should still generate VEM even with nil Operation
	assert.Len(t, specs, 1)
	assert.Equal(t, MCPPrimitive, specs[0].Status)
	assert.Equal(t, "nil-tool", specs[0].MCPPrimitiveMeta.Name)
	assert.Nil(t, specs[0].MCPPrimitiveMeta.Operation)
}

func Test_generateMCPVEMs_EmptyPrimitiveName(t *testing.T) {
	// Create an MCP API spec with empty primitive name
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"": {Allow: &oas.Allowance{Enabled: true}}, // empty name
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	// Should handle empty name gracefully
	assert.Len(t, specs, 1)
	assert.Equal(t, "", specs[0].MCPPrimitiveMeta.Name)
	assert.Contains(t, apiSpec.MCPPrimitives, "tool:")
	assert.Equal(t, "/mcp-tool:", apiSpec.MCPPrimitives["tool:"])
}

func Test_generateMCPVEMs_DuplicateNamesAcrossTypes(t *testing.T) {
	// Same name used as tool, resource, and prompt
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"shared-name": {Allow: &oas.Allowance{Enabled: true}},
			},
			McpResources: map[string]*oas.Operation{
				"shared-name": {Allow: &oas.Allowance{Enabled: true}},
			},
			McpPrompts: map[string]*oas.Operation{
				"shared-name": {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	// Should create separate VEMs for each type
	assert.Len(t, specs, 3)
	assert.Len(t, apiSpec.MCPPrimitives, 3)

	// Each type should have its own entry with different path
	assert.Equal(t, "/mcp-tool:shared-name", apiSpec.MCPPrimitives["tool:shared-name"])
	assert.Equal(t, "/mcp-resource:shared-name", apiSpec.MCPPrimitives["resource:shared-name"])
	assert.Equal(t, "/mcp-prompt:shared-name", apiSpec.MCPPrimitives["prompt:shared-name"])
}

func Test_generateMCPVEMs_VerifyRegexGeneration(t *testing.T) {
	// Verify that regex is properly generated for path matching
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"my-tool": {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	require.Len(t, specs, 1)
	// Verify the spec has a regex set
	assert.NotNil(t, specs[0].spec, "URLSpec should have compiled regex")

	// Test that the regex matches the expected path
	if specs[0].spec != nil {
		assert.True(t, specs[0].spec.MatchString("/mcp-tool:my-tool"), "regex should match VEM path")
		assert.False(t, specs[0].spec.MatchString("/mcp-tool:other-tool"), "regex should not match different tool")
	}
}

func Test_generateMCPVEMs_LargePrimitiveName(t *testing.T) {
	// Test with a very long primitive name
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	longName := strings.Repeat("a", 1000)
	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				longName: {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 1)
	assert.Equal(t, longName, specs[0].MCPPrimitiveMeta.Name)
}

func Test_generateMCPVEMs_SpecialRegexCharactersInName(t *testing.T) {
	// Names containing regex special characters that could break pattern matching
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	// Note: Some special characters might need escaping for regex
	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"tool.with.dots":        {Allow: &oas.Allowance{Enabled: true}},
				"tool-with-hyphens":     {Allow: &oas.Allowance{Enabled: true}},
				"tool_with_underscores": {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Len(t, specs, 3)
	assert.Len(t, apiSpec.MCPPrimitives, 3)
}

func Test_MCPPrimitives_MapAlreadyInitialized(t *testing.T) {
	// Test that if MCPPrimitives is already initialized, it's not overwritten
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS:           oas.OAS{},
		MCPPrimitives: map[string]string{"existing": "value"},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.Operation{
				"new-tool": {Allow: &oas.Allowance{Enabled: true}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	loader.generateMCPVEMs(apiSpec, config.Config{})

	// Should preserve existing entry and add new one
	assert.Contains(t, apiSpec.MCPPrimitives, "existing")
	assert.Equal(t, "value", apiSpec.MCPPrimitives["existing"])
	assert.Contains(t, apiSpec.MCPPrimitives, "tool:new-tool")
}

func Test_IsMCP_EdgeCases(t *testing.T) {
	tests := []struct {
		name                string
		jsonRpcVersion      string
		applicationProtocol string
		expected            bool
	}{
		{
			name:                "both set correctly",
			jsonRpcVersion:      apidef.JsonRPC20,
			applicationProtocol: apidef.AppProtocolMCP,
			expected:            true,
		},
		{
			name:                "only jsonRpcVersion set",
			jsonRpcVersion:      apidef.JsonRPC20,
			applicationProtocol: "",
			expected:            false,
		},
		{
			name:                "only applicationProtocol set",
			jsonRpcVersion:      "",
			applicationProtocol: apidef.AppProtocolMCP,
			expected:            true, // IsMCP only checks ApplicationProtocol
		},
		{
			name:                "different protocol",
			jsonRpcVersion:      apidef.JsonRPC20,
			applicationProtocol: "a2a",
			expected:            false,
		},
		{
			name:                "both empty",
			jsonRpcVersion:      "",
			applicationProtocol: "",
			expected:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					JsonRpcVersion:      tt.jsonRpcVersion,
					ApplicationProtocol: tt.applicationProtocol,
				},
			}
			assert.Equal(t, tt.expected, apiSpec.IsMCP())
		})
	}
}

func Test_URLAllowedAndIgnored_MCPPrimitive_PathNotMatching(t *testing.T) {
	// Test when path has VEM prefix but doesn't match specific tool
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
	}

	// Create RxPaths with MCPPrimitive entry for "get-weather"
	rxPaths := []URLSpec{
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "get-weather",
				Type:   "tool",
				Method: "POST",
			},
		},
	}
	rxPaths[0].spec = mustCompileRegex("/mcp-tool:get-weather$")

	// Request to a different tool path
	r := httptest.NewRequest("POST", "/mcp-tool:different-tool", nil)

	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)

	// Should NOT be blocked because path doesn't match
	assert.NotEqual(t, EndPointNotAllowed, status)
}

func Test_URLAllowedAndIgnored_MultipleMCPPrimitives(t *testing.T) {
	// Test with multiple MCP primitives in rxPaths
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
	}

	rxPaths := []URLSpec{
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "tool-a",
				Type:   "tool",
				Method: "POST",
			},
		},
		{
			Status: MCPPrimitive,
			MCPPrimitiveMeta: MCPPrimitiveMeta{
				Name:   "tool-b",
				Type:   "tool",
				Method: "POST",
			},
		},
	}
	rxPaths[0].spec = mustCompileRegex("/mcp-tool:tool-a")
	rxPaths[1].spec = mustCompileRegex("/mcp-tool:tool-b")

	// Request to tool-b without MCP routing
	r := httptest.NewRequest("POST", "/mcp-tool:tool-b", nil)

	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)

	// Should be blocked (direct access to MCP primitive)
	assert.Equal(t, EndPointNotAllowed, status)
}
