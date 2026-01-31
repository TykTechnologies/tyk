package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/regexp"
)

func Test_generateMCPVEMs_NonMCPAPI(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: "",
			JsonRpcVersion:      "",
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"get-weather": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Nil(t, specs)
}

func Test_generateMCPVEMs_RequiresJSONRPC20(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      "1.0",
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"get-weather": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Nil(t, specs)
}

func Test_generateMCPVEMs_NoMiddleware(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		OAS: oas.OAS{},
	}

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})

	assert.Nil(t, specs)
}

func Test_generateMCPVEMs_GeneratesVEMsAndMiddlewareSpecs(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"get-weather": {Operation: oas.Operation{
					Allow:     &oas.Allowance{Enabled: true},
					RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 100, Per: oas.ReadableDuration(time.Minute)},
				}},
			},
			McpResources: oas.MCPPrimitives{
				"file:///repo/*": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
			},
			McpPrompts: oas.MCPPrimitives{
				"code-review": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	conf := config.Config{
		HttpServerOptions: config.HttpServerOptionsConfig{
			EnablePathPrefixMatching: true,
			EnablePathSuffixMatching: true,
		},
	}
	specs := loader.generateMCPVEMs(apiSpec, conf)
	require.NotEmpty(t, specs)

	// Registry contains raw VEM paths (no sanitization).
	assert.Equal(t, "/mcp-tool:get-weather", apiSpec.MCPPrimitives["tool:get-weather"])
	assert.Equal(t, "/mcp-resource:file:///repo/*", apiSpec.MCPPrimitives["resource:file:///repo/*"])
	assert.Equal(t, "/mcp-prompt:code-review", apiSpec.MCPPrimitives["prompt:code-review"])

	// Base internal entry exists for access control.
	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	base, ok := apiSpec.FindSpecMatchesStatus(r, specs, Internal)
	require.True(t, ok)
	assert.Equal(t, http.MethodPost, base.Internal.Method)
	assert.Equal(t, "/mcp-tool:get-weather", base.Internal.Path)

	// RateLimit middleware spec exists for the VEM path.
	rl, ok := apiSpec.FindSpecMatchesStatus(r, specs, RateLimit)
	require.True(t, ok)
	assert.Equal(t, http.MethodPost, rl.RateLimit.Method)
	assert.Equal(t, 100.0, rl.RateLimit.Rate)
	assert.Equal(t, 60.0, rl.RateLimit.Per)
}

func Test_generateMCPVEMs_RateLimitedToolVEM(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/",
			},
		},
		OAS: oas.OAS{},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"get-weather": {Operation: oas.Operation{RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 5, Per: oas.ReadableDuration(10 * time.Second)}}},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})
	require.NotEmpty(t, specs)

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	rl, ok := apiSpec.FindSpecMatchesStatus(r, specs, RateLimit)
	require.True(t, ok)
	assert.Equal(t, http.MethodPost, rl.RateLimit.Method)
	assert.Equal(t, 5.0, rl.RateLimit.Rate)
	assert.Equal(t, 10.0, rl.RateLimit.Per)
}

func Test_URLAllowedAndIgnored_MCPPrimitive_DirectAccess_ReturnsNotFoundStatus(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
	assert.Equal(t, MCPPrimitiveNotFound, status)
}

func Test_URLAllowedAndIgnored_MCPPrimitive_MCPRouting_Allows(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	httpctx.SetJsonRPCRouting(r, true)
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
	assert.NotEqual(t, MCPPrimitiveNotFound, status)
}

func Test_VersionCheck_MCPPrimitiveDirectAccess_Returns404(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions: map[string]apidef.VersionInfo{
					"Default": {Name: "Default"},
				},
			},
		},
		RxPaths:          map[string][]URLSpec{},
		WhiteListEnabled: map[string]bool{},
	}

	loader := APIDefinitionLoader{}
	spec.RxPaths["Default"] = loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")
	spec.WhiteListEnabled["Default"] = false

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	ctxSetVersionInfo(r, &apidef.VersionInfo{Name: "Default"})

	vc := &VersionCheck{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	w := httptest.NewRecorder()

	err, code := vc.ProcessRequest(w, r, nil)
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, code)
}

func Test_MCPPrimitiveRegex_IsLiteral(t *testing.T) {
	loader := APIDefinitionLoader{}

	tool := "/mcp-tool:tool.with.dots"
	toolSpecs := loader.buildPrimitiveSpec("tool.with.dots", "tool", tool)
	require.Len(t, toolSpecs, 1)
	require.NotNil(t, toolSpecs[0].spec)
	assert.True(t, toolSpecs[0].spec.MatchString(tool))
	assert.False(t, toolSpecs[0].spec.MatchString("/mcp-tool:toolXwithXdots"))

	resPath := "/mcp-resource:file:///repo/*"
	resSpecs := loader.buildPrimitiveSpec("file:///repo/*", "resource", resPath)
	require.Len(t, resSpecs, 1)
	require.NotNil(t, resSpecs[0].spec)
	assert.True(t, resSpecs[0].spec.MatchString(resPath))
	assert.False(t, resSpecs[0].spec.MatchString("/mcp-resource:file:///repo/anything"))
}

func Test_MCPPrefixes_NotEmpty(t *testing.T) {
	if mcp.ToolPrefix == "" || mcp.ResourcePrefix == "" || mcp.PromptPrefix == "" {
		t.Fatalf("mcp prefixes must not be empty")
	}
}

func Test_MCPWhiteListMatching(t *testing.T) {
	// Debug test to verify WhiteList matching for MCP VEM paths
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}

	// Create a WhiteList entry for /mcp-tool:tool-allowed
	whiteList := loader.compileExtendedPathSpec(false, []apidef.EndPointMeta{
		{Path: "/mcp-tool:tool-allowed", Method: http.MethodPost, Disabled: false},
	}, WhiteList, config.Config{})

	require.Len(t, whiteList, 1, "should have 1 WhiteList entry")
	t.Logf("WhiteList spec: %+v", whiteList[0])
	t.Logf("WhiteList regex pattern: %v", whiteList[0].spec)

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:tool-allowed", nil)
	status, _ := apiSpec.URLAllowedAndIgnored(r, whiteList, true)
	assert.Equal(t, StatusOk, status, "WhiteList should match and return StatusOk")
}

func Test_MCPAllowListWithCatchAll(t *testing.T) {
	// Test that catch-all BlackList works correctly with WhiteList entries.
	// When MCPAllowListEnabled is true:
	// - tool-allowed has Internal + WhiteList entry → WhiteList grants access → passes
	// - tool-not-allowed has Internal but NO WhiteList → caught by catch-all → blocked
	// - unregistered-tool has no entries → caught by catch-all → blocked

	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
		MCPAllowListEnabled: true,
	}

	conf := config.Config{
		HttpServerOptions: config.HttpServerOptionsConfig{
			EnablePathPrefixMatching: true,
			EnablePathSuffixMatching: true,
		},
	}
	loader := APIDefinitionLoader{}

	// Build specs for tool-allowed (with Allow) - gets Internal + WhiteList
	allowedInternal := loader.buildPrimitiveSpec("tool-allowed", "tool", "/mcp-tool:tool-allowed")
	allowedWhiteList := loader.compileExtendedPathSpec(false, []apidef.EndPointMeta{
		{Path: "/mcp-tool:tool-allowed", Method: http.MethodPost, Disabled: false},
	}, WhiteList, conf)

	// tool-not-allowed (without Allow) gets NO Internal entry when allowListEnabled
	// It will be caught by the catch-all BlackList

	// Build catch-all BlackList for all categories
	catchAllPrefixes := []string{
		"/json-rpc-method:/*",
		mcp.ToolPrefix + "/*",
		mcp.ResourcePrefix + "/*",
		mcp.PromptPrefix + "/*",
	}
	catchAll := loader.buildCatchAllSpecs(catchAllPrefixes, conf)

	// Combine in order: specific entries first, catch-all last
	rxPaths := []URLSpec{}
	rxPaths = append(rxPaths, allowedInternal...)
	rxPaths = append(rxPaths, allowedWhiteList...)
	// No notAllowedInternal - that's the key change!
	rxPaths = append(rxPaths, catchAll...)

	t.Run("tool-allowed with WhiteList passes", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp-tool:tool-allowed", nil)
		httpctx.SetJsonRPCRouting(r, true)
		status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true)
		// Internal entry allows routing, WhiteList entry grants access
		assert.Equal(t, StatusOk, status)
	})

	t.Run("tool-not-allowed without WhiteList blocked by catch-all", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp-tool:tool-not-allowed", nil)
		httpctx.SetJsonRPCRouting(r, true)
		status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true)
		// No Internal entry, caught by catch-all BlackList
		assert.Equal(t, EndPointNotAllowed, status)
	})

	t.Run("unregistered-tool blocked by catch-all", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp-tool:unregistered", nil)
		httpctx.SetJsonRPCRouting(r, true)
		status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true)
		// Should be blocked by catch-all BlackList (returns EndPointNotAllowed)
		assert.Equal(t, EndPointNotAllowed, status)
	})
}

func Test_hasMCPAllowListEnabled(t *testing.T) {
	tests := []struct {
		name       string
		categories []PrimitiveCategory
		want       bool
	}{
		{
			name:       "empty categories",
			categories: []PrimitiveCategory{},
			want:       false,
		},
		{
			name: "no primitives",
			categories: []PrimitiveCategory{
				{TypeName: "tool", Primitives: oas.MCPPrimitives{}},
			},
			want: false,
		},
		{
			name: "primitive with nil allow",
			categories: []PrimitiveCategory{
				{
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool1": {Operation: oas.Operation{Allow: nil}},
					},
				},
			},
			want: false,
		},
		{
			name: "primitive with allow disabled",
			categories: []PrimitiveCategory{
				{
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: false}}},
					},
				},
			},
			want: false,
		},
		{
			name: "primitive with allow enabled",
			categories: []PrimitiveCategory{
				{
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
					},
				},
			},
			want: true,
		},
		{
			name: "multiple categories one with allow enabled",
			categories: []PrimitiveCategory{
				{
					TypeName: "tool",
					Primitives: oas.MCPPrimitives{
						"tool1": {Operation: oas.Operation{Allow: nil}},
					},
				},
				{
					TypeName: "resource",
					Primitives: oas.MCPPrimitives{
						"resource1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
					},
				},
			},
			want: true,
		},
		{
			name: "nil primitive in map",
			categories: []PrimitiveCategory{
				{
					TypeName:   "tool",
					Primitives: oas.MCPPrimitives{"tool1": nil},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasMCPAllowListEnabled(tt.categories)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_generateMCPVEMs_SetsOperationsAllowListEnabled(t *testing.T) {
	// Test that OperationsAllowListEnabled flag is set when operations have allow enabled
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/mcp",
			},
		},
		OAS: oas.OAS{
			T: openapi3.T{
				Paths: func() *openapi3.Paths {
					paths := openapi3.NewPaths()
					paths.Set("/tools/call", &openapi3.PathItem{
						Post: &openapi3.Operation{OperationID: "tools-call-op"},
					})
					return paths
				}(),
			},
		},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"dummy-tool": &oas.MCPPrimitive{}, // Need at least one primitive for MCP API
			},
			Operations: oas.Operations{
				"tools-call-op": {
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPVEMs(apiSpec, config.Config{
		HttpServerOptions: config.HttpServerOptionsConfig{
			EnablePathPrefixMatching: true,
			EnablePathSuffixMatching: true,
		},
	})

	// Check flags are set correctly
	assert.True(t, apiSpec.OperationsAllowListEnabled, "OperationsAllowListEnabled should be true when operation has allow")
	assert.False(t, apiSpec.MCPAllowListEnabled, "MCPAllowListEnabled should be false when no primitive has allow")

	// Check that catch-all BlackList VEM is generated for operations
	foundCatchAll := false
	for _, spec := range specs {
		if spec.Status == BlackList && spec.spec != nil {
			pattern := spec.spec.String()
			if strings.Contains(pattern, "json-rpc-method") {
				foundCatchAll = true
				break
			}
		}
	}
	assert.True(t, foundCatchAll, "should generate catch-all BlackList VEM for operations when OperationsAllowListEnabled is true")
}

func Test_generateMCPVEMs_SetsMCPAllowListEnabled(t *testing.T) {
	tests := []struct {
		name       string
		middleware *oas.Middleware
		want       bool
	}{
		{
			name: "no allow rules",
			middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"tool1": {Operation: oas.Operation{RateLimit: &oas.RateLimitEndpoint{Enabled: true}}},
				},
			},
			want: false,
		},
		{
			name: "allow rule disabled",
			middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"tool1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: false}}},
				},
			},
			want: false,
		},
		{
			name: "allow rule enabled on tool",
			middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"tool1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
				},
			},
			want: true,
		},
		{
			name: "allow rule enabled on resource",
			middleware: &oas.Middleware{
				McpResources: oas.MCPPrimitives{
					"file:///repo/*": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
				},
			},
			want: true,
		},
		{
			name: "allow rule enabled on prompt",
			middleware: &oas.Middleware{
				McpPrompts: oas.MCPPrimitives{
					"prompt1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
				},
			},
			want: true,
		},
		{
			name: "mixed primitives with one allow enabled",
			middleware: &oas.Middleware{
				McpTools: oas.MCPPrimitives{
					"tool1": {Operation: oas.Operation{RateLimit: &oas.RateLimitEndpoint{Enabled: true}}},
				},
				McpResources: oas.MCPPrimitives{
					"resource1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: false}}},
				},
				McpPrompts: oas.MCPPrimitives{
					"prompt1": {Operation: oas.Operation{Allow: &oas.Allowance{Enabled: true}}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: apidef.AppProtocolMCP,
					JsonRpcVersion:      apidef.JsonRPC20,
				},
				OAS: oas.OAS{},
			}

			tykExt := &oas.XTykAPIGateway{Middleware: tt.middleware}
			apiSpec.OAS.SetTykExtension(tykExt)

			loader := APIDefinitionLoader{}
			loader.generateMCPVEMs(apiSpec, config.Config{})

			assert.Equal(t, tt.want, apiSpec.MCPAllowListEnabled)
		})
	}
}

func Test_URLAllowedAndIgnored_MCPPrimitive_LoopingAlone_DoesNotAllow(t *testing.T) {
	// Verifies that generic looping (ctxLoopLevel > 0) does NOT grant access to MCP primitives.
	// MCP primitives specifically require httpctx.IsJsonRPCRouting to be set.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	ctxSetLoopLevel(r, 1) // Generic looping enabled, but NOT MCP routing
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
	assert.Equal(t, MCPPrimitiveNotFound, status, "MCP primitive should not be accessible via generic looping alone")
}

func Test_URLAllowedAndIgnored_RegularInternal_Looping_Allows(t *testing.T) {
	// Verifies that regular (non-MCP) internal endpoints still work with generic looping.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	rxPaths := []URLSpec{
		{
			Status: Internal,
			Internal: apidef.InternalMeta{
				Path:   "/internal-endpoint",
				Method: http.MethodGet,
			},
		},
	}
	// Compile the regex for path matching
	rxPaths[0].spec, _ = regexp.Compile("^/internal-endpoint$")

	r := httptest.NewRequest(http.MethodGet, "/internal-endpoint", nil)
	ctxSetLoopLevel(r, 1) // Generic looping enabled
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
	assert.NotEqual(t, EndPointNotAllowed, status, "Regular internal endpoint should be accessible via generic looping")
}

func Test_URLAllowedAndIgnored_RegularInternal_NoLooping_Blocks(t *testing.T) {
	// Verifies that regular internal endpoints are blocked without looping.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	rxPaths := []URLSpec{
		{
			Status: Internal,
			Internal: apidef.InternalMeta{
				Path:   "/internal-endpoint",
				Method: http.MethodGet,
			},
		},
	}
	rxPaths[0].spec, _ = regexp.Compile("^/internal-endpoint$")

	r := httptest.NewRequest(http.MethodGet, "/internal-endpoint", nil)
	// No looping, no MCP routing
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
	assert.Equal(t, EndPointNotAllowed, status, "Regular internal endpoint should be blocked without looping")
}

func Test_URLAllowedAndIgnored_MCPPrimitive_WhitelistMode_MCPRouting_WithoutWhiteList_Blocks(t *testing.T) {
	// Verifies MCP primitives with only Internal entry (no WhiteList) are blocked in whitelist mode.
	// In allow list mode, having Internal entry allows routing but not access - you need WhiteList for access.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	httpctx.SetJsonRPCRouting(r, true)
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true) // whiteListStatus = true
	// No WhiteList entry means blocked in whitelist mode (endpoint not allowed at end of loop)
	assert.Equal(t, EndPointNotAllowed, status, "MCP primitive without WhiteList should be blocked in whitelist mode")
}

func Test_URLAllowedAndIgnored_MCPPrimitive_WhitelistMode_NoMCPRouting_Blocks(t *testing.T) {
	// Verifies MCP primitives are blocked in whitelist mode without MCPRouting.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	// No MCPRouting set
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true) // whiteListStatus = true
	assert.Equal(t, MCPPrimitiveNotFound, status, "MCP primitive should return 404 in whitelist mode without MCPRouting")
}

func Test_URLAllowedAndIgnored_MCPPrimitive_WhitelistMode_LoopingAlone_Blocks(t *testing.T) {
	// Verifies that generic looping doesn't grant MCP access in whitelist mode.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	ctxSetLoopLevel(r, 1)                                       // Generic looping but NOT MCPRouting
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true) // whiteListStatus = true
	assert.Equal(t, MCPPrimitiveNotFound, status, "MCP primitive should not be accessible via generic looping in whitelist mode")
}

func Test_URLAllowedAndIgnored_RegularInternal_WhitelistMode_Looping_Allows(t *testing.T) {
	// Verifies regular internal endpoints work with looping in whitelist mode.
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	rxPaths := []URLSpec{
		{
			Status: Internal,
			Internal: apidef.InternalMeta{
				Path:   "/internal-endpoint",
				Method: http.MethodGet,
			},
		},
	}
	rxPaths[0].spec, _ = regexp.Compile("^/internal-endpoint$")

	r := httptest.NewRequest(http.MethodGet, "/internal-endpoint", nil)
	ctxSetLoopLevel(r, 1)
	status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, true) // whiteListStatus = true
	assert.Equal(t, StatusInternal, status, "Regular internal endpoint should be allowed with looping in whitelist mode")
}

func Test_MCPRoutingContext_SetAndGet(t *testing.T) {
	// Verifies the httpctx.SetJsonRPCRouting and IsJsonRPCRouting functions work correctly.
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	// Initially should be false
	assert.False(t, httpctx.IsJsonRPCRouting(r), "MCPRouting should be false by default")

	// Set to true
	httpctx.SetJsonRPCRouting(r, true)
	assert.True(t, httpctx.IsJsonRPCRouting(r), "MCPRouting should be true after setting")

	// Set to false
	httpctx.SetJsonRPCRouting(r, false)
	assert.False(t, httpctx.IsJsonRPCRouting(r), "MCPRouting should be false after unsetting")
}

func Test_URLAllowedAndIgnored_AllMCPPrimitiveTypes(t *testing.T) {
	// Verifies all MCP primitive types (tool, resource, prompt) require MCPRouting.
	tests := []struct {
		name   string
		prefix string
	}{
		{"tool", mcp.ToolPrefix},
		{"resource", mcp.ResourcePrefix},
		{"prompt", mcp.PromptPrefix},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{ListenPath: "/"},
				},
			}

			loader := APIDefinitionLoader{}
			path := tt.prefix + "test-primitive"
			rxPaths := loader.buildPrimitiveSpec("test-primitive", tt.name, path)

			// Without MCPRouting - should block
			r := httptest.NewRequest(http.MethodPost, path, nil)
			status, _ := apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
			assert.Equal(t, MCPPrimitiveNotFound, status, "%s primitive should be blocked without MCPRouting", tt.name)

			// With MCPRouting - should allow
			r = httptest.NewRequest(http.MethodPost, path, nil)
			httpctx.SetJsonRPCRouting(r, true)
			status, _ = apiSpec.URLAllowedAndIgnored(r, rxPaths, false)
			assert.NotEqual(t, MCPPrimitiveNotFound, status, "%s primitive should be allowed with MCPRouting", tt.name)
		})
	}
}

func Test_findOperationID(t *testing.T) {
	tests := []struct {
		name       string
		pathItem   *openapi3.PathItem
		expectedID string
	}{
		{
			name: "GET operation",
			pathItem: &openapi3.PathItem{
				Get: &openapi3.Operation{OperationID: "getOperation"},
			},
			expectedID: "getOperation",
		},
		{
			name: "POST operation",
			pathItem: &openapi3.PathItem{
				Post: &openapi3.Operation{OperationID: "postOperation"},
			},
			expectedID: "postOperation",
		},
		{
			name: "multiple operations - returns first",
			pathItem: &openapi3.PathItem{
				Get:  &openapi3.Operation{OperationID: "getOp"},
				Post: &openapi3.Operation{OperationID: "postOp"},
			},
			expectedID: "getOp", // GET is checked first
		},
		{
			name: "operation without ID",
			pathItem: &openapi3.PathItem{
				Get: &openapi3.Operation{OperationID: ""},
			},
			expectedID: "",
		},
		{
			name:       "nil pathItem",
			pathItem:   nil,
			expectedID: "",
		},
		{
			name:       "empty pathItem",
			pathItem:   &openapi3.PathItem{},
			expectedID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pathItem == nil {
				// Skip nil test as the function requires non-nil input
				return
			}
			result := findOperationID(tt.pathItem)
			assert.Equal(t, tt.expectedID, result)
		})
	}
}

func Test_generateMCPOperationVEMs_PathMatching(t *testing.T) {
	// Test that operation VEMs are generated based on OAS path matching
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/mcp",
			},
		},
		OAS: oas.OAS{
			T: openapi3.T{
				Paths: func() *openapi3.Paths {
					paths := openapi3.NewPaths()
					paths.Set("/tools/call", &openapi3.PathItem{
						Get: &openapi3.Operation{OperationID: "myToolsCallOp"},
					})
					return paths
				}(),
			},
		},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: map[string]*oas.Operation{
				"myToolsCallOp": {
					RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 10, Per: oas.ReadableDuration(time.Minute)},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPOperationVEMs(apiSpec, config.Config{})

	// Should generate specs for the /tools/call path
	require.NotEmpty(t, specs)

	// Find the rate limit spec
	var foundRateLimit bool
	for _, spec := range specs {
		if spec.Status == RateLimit && spec.RateLimit.Path == "/json-rpc-method:tools/call" {
			foundRateLimit = true
			assert.Equal(t, 10.0, spec.RateLimit.Rate)
			break
		}
	}
	assert.True(t, foundRateLimit, "should generate rate limit spec for operation VEM")
}

func Test_generateMCPOperationVEMs_HeaderInjection(t *testing.T) {
	// Test that operation VEMs generate header injection specs correctly
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
			Proxy: apidef.ProxyConfig{
				ListenPath: "/mcp",
			},
		},
		OAS: oas.OAS{
			T: openapi3.T{
				Paths: func() *openapi3.Paths {
					paths := openapi3.NewPaths()
					paths.Set("/tools/call", &openapi3.PathItem{
						Get: &openapi3.Operation{OperationID: "testget"},
					})
					return paths
				}(),
			},
		},
	}

	tykExt := &oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: map[string]*oas.Operation{
				"testget": {
					TransformRequestHeaders: &oas.TransformHeaders{
						Enabled: true,
						Add: []oas.Header{
							{Name: "X-Operation-Header", Value: "operation-value"},
						},
					},
				},
			},
		},
	}
	apiSpec.OAS.SetTykExtension(tykExt)

	loader := APIDefinitionLoader{}
	specs := loader.generateMCPOperationVEMs(apiSpec, config.Config{})

	// Should generate specs for the /tools/call path
	require.NotEmpty(t, specs, "should generate VEM specs")

	// Debug: print all specs
	t.Logf("Generated %d specs:", len(specs))
	for i, spec := range specs {
		t.Logf("  [%d] Status=%d", i, spec.Status)
		if spec.Status == HeaderInjected {
			t.Logf("      HeaderInjected: Path=%s, Method=%s, Add=%v",
				spec.InjectHeaders.Path, spec.InjectHeaders.Method, spec.InjectHeaders.AddHeaders)
		}
		if spec.Status == Internal {
			t.Logf("      Internal: Path=%s, Method=%s", spec.Internal.Path, spec.Internal.Method)
		}
	}

	// Find the header injection spec
	var foundHeaderInjected bool
	for _, spec := range specs {
		if spec.Status == HeaderInjected && spec.InjectHeaders.Path == "/json-rpc-method:tools/call" {
			foundHeaderInjected = true
			assert.Equal(t, http.MethodPost, spec.InjectHeaders.Method)
			assert.Contains(t, spec.InjectHeaders.AddHeaders, "X-Operation-Header")
			assert.Equal(t, "operation-value", spec.InjectHeaders.AddHeaders["X-Operation-Header"])
			break
		}
	}
	assert.True(t, foundHeaderInjected, "should generate header injection spec for operation VEM")
}
