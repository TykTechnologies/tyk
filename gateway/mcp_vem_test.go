package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
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
				"get-weather": {Operation: oas.Operation{RateLimit: &oas.RateLimitEndpoint{Enabled: true, Rate: 100, Per: oas.ReadableDuration(time.Minute)}}},
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
	specs := loader.generateMCPVEMs(apiSpec, config.Config{})
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

func Test_URLAllowedAndIgnored_MCPPrimitive_Looping_Allows(t *testing.T) {
	apiSpec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/"},
		},
	}

	loader := APIDefinitionLoader{}
	rxPaths := loader.buildPrimitiveSpec("get-weather", "tool", "/mcp-tool:get-weather")

	r := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	ctxSetLoopLevel(r, 1)
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
