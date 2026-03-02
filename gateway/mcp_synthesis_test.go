package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/user"
)

func rateLimit(rate, per float64) user.RateLimit {
	return user.RateLimit{Rate: rate, Per: per}
}

// -- hasRateLimit --

func TestHasRateLimit_ZeroValue(t *testing.T) {
	assert.False(t, hasRateLimit(user.RateLimit{}))
}

func TestHasRateLimit_ZeroRateAndPer(t *testing.T) {
	assert.False(t, hasRateLimit(rateLimit(0, 0)))
}

func TestHasRateLimit_NonZero(t *testing.T) {
	assert.True(t, hasRateLimit(rateLimit(10, 60)))
}

// -- jsonRPCMethodEndpoints --

func TestJSONRPCMethodEndpoints_Empty(t *testing.T) {
	assert.Nil(t, jsonRPCMethodEndpoints(nil))
}

func TestJSONRPCMethodEndpoints_SkipsZeroLimit(t *testing.T) {
	methods := []user.JSONRPCMethodLimit{
		{Name: "tools/call", Limit: rateLimit(0, 0)},
	}
	assert.Nil(t, jsonRPCMethodEndpoints(methods))
}

func TestJSONRPCMethodEndpoints_ProducesVEMPaths(t *testing.T) {
	methods := []user.JSONRPCMethodLimit{
		{Name: "tools/call", Limit: rateLimit(10, 60)},
		{Name: "tools/list", Limit: rateLimit(5, 60)},
	}
	eps := jsonRPCMethodEndpoints(methods)
	assert.Len(t, eps, 2)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/call", eps[0].Path)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/list", eps[1].Path)
}

func TestJSONRPCMethodEndpoints_UsesHttpMethodPost(t *testing.T) {
	methods := []user.JSONRPCMethodLimit{
		{Name: "tools/call", Limit: rateLimit(10, 60)},
	}
	eps := jsonRPCMethodEndpoints(methods)
	assert.Equal(t, http.MethodPost, eps[0].Methods[0].Name)
}

func TestJSONRPCMethodEndpoints_PreservesLimit(t *testing.T) {
	limit := rateLimit(10, 60)
	methods := []user.JSONRPCMethodLimit{{Name: "tools/call", Limit: limit}}
	eps := jsonRPCMethodEndpoints(methods)
	assert.Equal(t, limit, eps[0].Methods[0].Limit)
}

// -- primitiveEndpoints --

func TestPrimitiveEndpoints_Empty(t *testing.T) {
	assert.Nil(t, primitiveEndpoints(nil))
}

func TestPrimitiveEndpoints_SkipsZeroLimit(t *testing.T) {
	primitives := []user.MCPPrimitiveLimit{
		{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(0, 0)},
	}
	assert.Nil(t, primitiveEndpoints(primitives))
}

func TestPrimitiveEndpoints_SkipsUnknownType(t *testing.T) {
	primitives := []user.MCPPrimitiveLimit{
		{Type: "unknown", Name: "something", Limit: rateLimit(10, 60)},
	}
	assert.Nil(t, primitiveEndpoints(primitives))
}

func TestPrimitiveEndpoints_AllTypes(t *testing.T) {
	primitives := []user.MCPPrimitiveLimit{
		{Type: mcp.PrimitiveTypeTool, Name: "my_tool", Limit: rateLimit(10, 60)},
		{Type: mcp.PrimitiveTypeResource, Name: "file:///data", Limit: rateLimit(10, 60)},
		{Type: mcp.PrimitiveTypePrompt, Name: "my_prompt", Limit: rateLimit(10, 60)},
	}
	eps := primitiveEndpoints(primitives)
	assert.Len(t, eps, 3)
	assert.Equal(t, mcp.ToolPrefix+"my_tool", eps[0].Path)
	assert.Equal(t, mcp.ResourcePrefix+"file:///data", eps[1].Path)
	assert.Equal(t, mcp.PromptPrefix+"my_prompt", eps[2].Path)
}

func TestPrimitiveEndpoints_UsesHttpMethodPost(t *testing.T) {
	primitives := []user.MCPPrimitiveLimit{
		{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 60)},
	}
	eps := primitiveEndpoints(primitives)
	assert.Equal(t, http.MethodPost, eps[0].Methods[0].Name)
}

func TestPrimitiveEndpoints_PreservesLimit(t *testing.T) {
	limit := rateLimit(5, 30)
	primitives := []user.MCPPrimitiveLimit{
		{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: limit},
	}
	eps := primitiveEndpoints(primitives)
	assert.Equal(t, limit, eps[0].Methods[0].Limit)
}

// -- synthesizeMCPEndpoints --

func TestSynthesizeMCPEndpoints_EmptyAccessDefinition(t *testing.T) {
	ad := &user.AccessDefinition{}
	synthesizeMCPEndpoints(ad)
	assert.Empty(t, ad.Endpoints)
}

func TestSynthesizeMCPEndpoints_JSONRPCMethodsOnly(t *testing.T) {
	ad := &user.AccessDefinition{
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: rateLimit(10, 60)},
			{Name: "tools/list", Limit: rateLimit(5, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 2)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/call", ad.Endpoints[0].Path)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/list", ad.Endpoints[1].Path)
}

func TestSynthesizeMCPEndpoints_MCPPrimitivesOnly(t *testing.T) {
	ad := &user.AccessDefinition{
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 1)
	assert.Equal(t, mcp.ToolPrefix+"get_weather", ad.Endpoints[0].Path)
}

func TestSynthesizeMCPEndpoints_AllPrimitiveTypes(t *testing.T) {
	ad := &user.AccessDefinition{
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "my_tool", Limit: rateLimit(10, 60)},
			{Type: mcp.PrimitiveTypeResource, Name: "file:///data", Limit: rateLimit(10, 60)},
			{Type: mcp.PrimitiveTypePrompt, Name: "my_prompt", Limit: rateLimit(10, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 3)
	assert.Equal(t, mcp.ToolPrefix+"my_tool", ad.Endpoints[0].Path)
	assert.Equal(t, mcp.ResourcePrefix+"file:///data", ad.Endpoints[1].Path)
	assert.Equal(t, mcp.PromptPrefix+"my_prompt", ad.Endpoints[2].Path)
}

func TestSynthesizeMCPEndpoints_SkipsZeroLimits(t *testing.T) {
	ad := &user.AccessDefinition{
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: rateLimit(0, 0)}, // zero — skip
			{Name: "tools/list", Limit: rateLimit(5, 60)},
		},
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(0, 0)}, // zero — skip
			{Type: mcp.PrimitiveTypeTool, Name: "get_forecast", Limit: rateLimit(3, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 2)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/list", ad.Endpoints[0].Path)
	assert.Equal(t, mcp.ToolPrefix+"get_forecast", ad.Endpoints[1].Path)
}

func TestSynthesizeMCPEndpoints_SkipsUnknownPrimitiveType(t *testing.T) {
	ad := &user.AccessDefinition{
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: "unknown", Name: "something", Limit: rateLimit(10, 60)},
			{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 1)
	assert.Equal(t, mcp.ToolPrefix+"get_weather", ad.Endpoints[0].Path)
}

func TestSynthesizeMCPEndpoints_PreservesExistingEndpoints(t *testing.T) {
	existing := user.Endpoint{Path: "/my/api", Methods: user.EndpointMethods{{Name: http.MethodGet}}}
	ad := &user.AccessDefinition{
		Endpoints: user.Endpoints{existing},
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: rateLimit(10, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 2)
	assert.Equal(t, "/my/api", ad.Endpoints[0].Path)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/call", ad.Endpoints[1].Path)
}

func TestSynthesizeMCPEndpoints_MethodIsHttpMethodPost(t *testing.T) {
	ad := &user.AccessDefinition{
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: rateLimit(10, 60)},
		},
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 60)},
		},
	}

	synthesizeMCPEndpoints(ad)

	for _, ep := range ad.Endpoints {
		for _, m := range ep.Methods {
			assert.Equal(t, http.MethodPost, m.Name)
		}
	}
}

func TestSynthesizeMCPEndpoints_LimitsArePreserved(t *testing.T) {
	ad := &user.AccessDefinition{
		JSONRPCMethods: []user.JSONRPCMethodLimit{
			{Name: "tools/call", Limit: rateLimit(10, 60)},
		},
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 30)},
		},
	}

	synthesizeMCPEndpoints(ad)

	assert.Equal(t, rateLimit(10, 60), ad.Endpoints[0].Methods[0].Limit)
	assert.Equal(t, rateLimit(5, 30), ad.Endpoints[1].Methods[0].Limit)
}

func TestNormalizeMCPEndpoints_EmptyAccessRights(t *testing.T) {
	session := &user.SessionState{}
	NormalizeMCPEndpoints(session)
	assert.Empty(t, session.AccessRights)
}

func TestNormalizeMCPEndpoints_MultipleAPIs(t *testing.T) {
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {
				JSONRPCMethods: []user.JSONRPCMethodLimit{
					{Name: "tools/call", Limit: rateLimit(10, 60)},
				},
			},
			"api-2": {
				MCPPrimitives: []user.MCPPrimitiveLimit{
					{Type: mcp.PrimitiveTypeTool, Name: "get_weather", Limit: rateLimit(5, 60)},
				},
			},
		},
	}

	NormalizeMCPEndpoints(session)

	assert.Len(t, session.AccessRights["api-1"].Endpoints, 1)
	assert.Equal(t, jsonrpc.MethodVEMPrefix+"tools/call", session.AccessRights["api-1"].Endpoints[0].Path)

	assert.Len(t, session.AccessRights["api-2"].Endpoints, 1)
	assert.Equal(t, mcp.ToolPrefix+"get_weather", session.AccessRights["api-2"].Endpoints[0].Path)
}

func TestSynthesizeMCPEndpoints_NoMCPFields_DoesNotTouchEndpoints(t *testing.T) {
	ad := &user.AccessDefinition{
		Endpoints: user.Endpoints{{Path: "/my/api"}},
		// No JSONRPCMethods or MCPPrimitives — must be a true no-op.
	}

	origPtr := &ad.Endpoints[0]
	synthesizeMCPEndpoints(ad)

	assert.Len(t, ad.Endpoints, 1)
	assert.Equal(t, "/my/api", ad.Endpoints[0].Path)
	assert.Same(t, origPtr, &ad.Endpoints[0], "Endpoints slice must not be reallocated for non-MCP access definitions")
}

func TestNormalizeMCPEndpoints_NoMCPFields(t *testing.T) {
	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-1": {Endpoints: user.Endpoints{{Path: "/my/api"}}},
		},
	}

	NormalizeMCPEndpoints(session)

	assert.Len(t, session.AccessRights["api-1"].Endpoints, 1)
	assert.Equal(t, "/my/api", session.AccessRights["api-1"].Endpoints[0].Path)
}
