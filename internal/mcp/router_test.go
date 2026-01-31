package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouter_ToolsCall_Found(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"tool:weather.getForecast": "/mcp-tool:weather.getForecast",
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "weather.getForecast",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "weather.getForecast", result.PrimitiveName)
	assert.Equal(t, []string{
		"/json-rpc-method:tools/call",
		"/mcp-tool:weather.getForecast",
	}, result.VEMChain)
}

func TestRouter_ToolsCall_NotFound(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "unknown-tool",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.False(t, result.Found)
	assert.Equal(t, "unknown-tool", result.PrimitiveName)
	assert.Equal(t, []string{"/json-rpc-method:tools/call"}, result.VEMChain)
}

func TestRouter_ToolsCall_NotFound_AllowListEnabled(t *testing.T) {
	router := NewRouter(true)
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "unknown-tool",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodToolsCall, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "unknown-tool", result.PrimitiveName)
	assert.Equal(t, []string{
		"/json-rpc-method:tools/call",
		"/mcp-tool:unknown-tool",
	}, result.VEMChain)
}

func TestRouter_ToolsCall_MissingParams(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{}

	_, err := router.RouteMethod(MethodToolsCall, nil, primitives)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "params")
}

func TestRouter_ToolsCall_MissingName(t *testing.T) {
	router := NewRouter(false)
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
	router := NewRouter(false)
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
	router := NewRouter(false)
	primitives := map[string]string{
		"resource:file:///data/config.json": "/mcp-resource:file:///data/config.json",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "file:///data/config.json", result.PrimitiveName)
	assert.Equal(t, []string{
		"/json-rpc-method:resources/read",
		"/mcp-resource:file:///data/config.json",
	}, result.VEMChain)
}

func TestRouter_ResourcesRead_WildcardMatch(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"resource:file:///data/*": "/mcp-resource:file:///data/*",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "file:///data/config.json", result.PrimitiveName)
	assert.Equal(t, []string{
		"/json-rpc-method:resources/read",
		"/mcp-resource:file:///data/*",
	}, result.VEMChain)
}

func TestRouter_ResourcesRead_ExactMatchBeatsWildcard(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"resource:file:///data/*":           "/mcp-resource:wildcard",
		"resource:file:///data/config.json": "/mcp-resource:exact",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/config.json",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "/mcp-resource:exact", result.VEMChain[1])
}

func TestRouter_ResourcesRead_LongerPrefixWins(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"resource:file:///data/*":     "/mcp-resource:short",
		"resource:file:///data/src/*": "/mcp-resource:long",
	}

	params, err := json.Marshal(map[string]interface{}{
		"uri": "file:///data/src/main.go",
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodResourcesRead, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "/mcp-resource:long", result.VEMChain[1])
}

func TestRouter_ResourcesRead_MissingURI(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{}

	params, err := json.Marshal(map[string]interface{}{})
	require.NoError(t, err)

	_, err = router.RouteMethod(MethodResourcesRead, params, primitives)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri")
}

func TestRouter_PromptsGet_Found(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"prompt:summarize": "/mcp-prompt:summarize",
	}

	params, err := json.Marshal(map[string]interface{}{
		"name":      "summarize",
		"arguments": map[string]interface{}{},
	})
	require.NoError(t, err)

	result, err := router.RouteMethod(MethodPromptsGet, params, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "summarize", result.PrimitiveName)
	assert.Equal(t, []string{
		"/json-rpc-method:prompts/get",
		"/mcp-prompt:summarize",
	}, result.VEMChain)
}

func TestRouter_Operation_Found(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{
		"operation:tools/list": "/json-rpc-method:tools-list",
	}

	result, err := router.RouteMethod("tools/list", nil, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, "tools/list", result.PrimitiveName)
	assert.Equal(t, []string{"/json-rpc-method:tools-list"}, result.VEMChain)
}

func TestRouter_Operation_NotFound(t *testing.T) {
	router := NewRouter(false)
	primitives := map[string]string{}

	result, err := router.RouteMethod("initialize", nil, primitives)

	require.NoError(t, err)
	assert.False(t, result.Found)
	assert.Equal(t, "initialize", result.PrimitiveName)
	assert.Equal(t, []string{"/json-rpc-method:initialize"}, result.VEMChain)
}

func TestRouter_Operation_AllowListEnabled(t *testing.T) {
	router := NewRouter(true)
	primitives := map[string]string{}

	result, err := router.RouteMethod("unknown-operation", nil, primitives)

	require.NoError(t, err)
	assert.True(t, result.Found)
	assert.Equal(t, []string{"/json-rpc-method:unknown-operation"}, result.VEMChain)
}
