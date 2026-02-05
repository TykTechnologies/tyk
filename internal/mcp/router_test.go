package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/jsonrpc"
)

func TestRouter_ToolsCall_Found(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"tool:weather.getForecast": ToolPrefix + "weather.getForecast",
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "weather.getForecast",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "weather.getForecast", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "tools/call",
		ToolPrefix + "weather.getForecast",
	}, result.VEMChain)
}

func TestRouter_ToolsCall_NotFound(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "unknown-tool",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "unknown-tool", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "tools/call",
		ToolPrefix + "unknown-tool",
	}, result.VEMChain)
}

func TestRouter_ToolsCall_NotFound_AllowListEnabled(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "unknown-tool",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "unknown-tool", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "tools/call",
		ToolPrefix + "unknown-tool",
	}, result.VEMChain)
}

func TestRouter_ToolsCall_MissingParams(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	_, err := router.RouteMethod(MethodToolsCall, nil, primitives)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "params")
}

func TestRouter_ToolsCall_MissingName(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	_, err = router.RouteMethod(MethodToolsCall, params, primitives)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestRouter_ToolsCall_EmptyName(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	_, err = router.RouteMethod(MethodToolsCall, params, primitives)

	require.Error(t, err)
}

func TestRouter_ResourcesRead_Found(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"resource:file:///data/config.json": ResourcePrefix + "file:///data/config.json",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "file:///data/config.json", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "resources/read",
		ResourcePrefix + "file:///data/config.json",
	}, result.VEMChain)
}

func TestRouter_ResourcesRead_WildcardMatch(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"resource:file:///data/*": ResourcePrefix + "file:///data/*",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "file:///data/config.json", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "resources/read",
		ResourcePrefix + "file:///data/*",
	}, result.VEMChain)
}

func TestRouter_ResourcesRead_ExactMatchBeatsWildcard(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"resource:file:///data/*":           ResourcePrefix + "wildcard",
		"resource:file:///data/config.json": ResourcePrefix + "exact",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, ResourcePrefix+"exact", result.VEMChain[1])
}

func TestRouter_ResourcesRead_LongerPrefixWins(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"resource:file:///data/*":     ResourcePrefix + "short",
		"resource:file:///data/src/*": ResourcePrefix + "long",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/src/main.go",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, ResourcePrefix+"long", result.VEMChain[1])
}

func TestRouter_ResourcesRead_MissingURI(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{})
	require.NoError(t, err)

	_, err = router.RouteMethod(MethodResourcesRead, params, primitives)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri")
}

func TestRouter_PromptsGet_Found(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"prompt:summarize": PromptPrefix + "summarize",
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "summarize",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodPromptsGet, params, primitives)

	require.NoError(t, err)
	assert.Equal(t, "summarize", result.PrimitiveName)
	assert.Equal(t, []string{
		jsonrpc.MethodVEMPrefix + "prompts/get",
		PromptPrefix + "summarize",
	}, result.VEMChain)
}

func TestRouter_Operation_Found(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{
		"operation:tools/list": jsonrpc.MethodVEMPrefix + "tools-list",
	}

	result, err := router.RouteMethod("tools/list", nil, primitives)

	require.NoError(t, err)
	assert.Equal(t, "tools/list", result.PrimitiveName)
	assert.Equal(t, []string{jsonrpc.MethodVEMPrefix + "tools-list"}, result.VEMChain)
}

func TestRouter_Operation_NotFound(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	result, err := router.RouteMethod("initialize", nil, primitives)

	require.NoError(t, err)
	assert.Equal(t, "initialize", result.PrimitiveName)
	assert.Equal(t, []string{jsonrpc.MethodVEMPrefix + "initialize"}, result.VEMChain)
}

func TestRouter_Operation_AllowListEnabled(t *testing.T) {
	router := NewRouter()
	primitives := map[string]string{}

	result, err := router.RouteMethod("unknown-operation", nil, primitives)

	require.NoError(t, err)
	assert.Equal(t, []string{jsonrpc.MethodVEMPrefix + "unknown-operation"}, result.VEMChain)
}
