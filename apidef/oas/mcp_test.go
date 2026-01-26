package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMiddleware_MCPTools(t *testing.T) {
	t.Run("mcpTools field marshaling", func(t *testing.T) {
		middleware := Middleware{
			McpTools: map[string]*Operation{
				"get-weather": {
					Allow: &Allowance{
						Enabled: true,
					},
				},
			},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		var result Middleware
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotNil(t, result.McpTools)
		assert.Equal(t, 1, len(result.McpTools))
		assert.NotNil(t, result.McpTools["get-weather"])
		assert.NotNil(t, result.McpTools["get-weather"].Allow)
		assert.True(t, result.McpTools["get-weather"].Allow.Enabled)
	})

	t.Run("empty mcpTools omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpTools: map[string]*Operation{},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpTools")
	})

	t.Run("nil mcpTools omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpTools: nil,
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpTools")
	})
}

func TestMiddleware_MCPResources(t *testing.T) {
	t.Run("mcpResources field marshaling", func(t *testing.T) {
		middleware := Middleware{
			McpResources: map[string]*Operation{
				"file:///repo/*": {
					Allow: &Allowance{
						Enabled: true,
					},
				},
			},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		var result Middleware
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotNil(t, result.McpResources)
		assert.Equal(t, 1, len(result.McpResources))
		assert.NotNil(t, result.McpResources["file:///repo/*"])
		assert.NotNil(t, result.McpResources["file:///repo/*"].Allow)
		assert.True(t, result.McpResources["file:///repo/*"].Allow.Enabled)
	})

	t.Run("empty mcpResources omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpResources: map[string]*Operation{},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpResources")
	})

	t.Run("nil mcpResources omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpResources: nil,
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpResources")
	})
}

func TestMiddleware_MCPPrompts(t *testing.T) {
	t.Run("mcpPrompts field marshaling", func(t *testing.T) {
		middleware := Middleware{
			McpPrompts: map[string]*Operation{
				"code-review": {
					Allow: &Allowance{
						Enabled: true,
					},
				},
			},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		var result Middleware
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.NotNil(t, result.McpPrompts)
		assert.Equal(t, 1, len(result.McpPrompts))
		assert.NotNil(t, result.McpPrompts["code-review"])
		assert.NotNil(t, result.McpPrompts["code-review"].Allow)
		assert.True(t, result.McpPrompts["code-review"].Allow.Enabled)
	})

	t.Run("empty mcpPrompts omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpPrompts: map[string]*Operation{},
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpPrompts")
	})

	t.Run("nil mcpPrompts omitted in JSON", func(t *testing.T) {
		middleware := Middleware{
			McpPrompts: nil,
		}

		data, err := json.Marshal(middleware)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "mcpPrompts")
	})
}

func TestMiddleware_ExtractTo_MCPDetection(t *testing.T) {
	t.Run("sets protocol flags when mcpTools present", func(t *testing.T) {
		middleware := Middleware{
			McpTools: map[string]*Operation{
				"get-weather": {
					Allow: &Allowance{Enabled: true},
				},
			},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Equal(t, apidef.JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, apidef.AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("sets protocol flags when mcpResources present", func(t *testing.T) {
		middleware := Middleware{
			McpResources: map[string]*Operation{
				"file:///repo/*": {
					Allow: &Allowance{Enabled: true},
				},
			},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Equal(t, apidef.JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, apidef.AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("sets protocol flags when mcpPrompts present", func(t *testing.T) {
		middleware := Middleware{
			McpPrompts: map[string]*Operation{
				"code-review": {
					Allow: &Allowance{Enabled: true},
				},
			},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Equal(t, apidef.JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, apidef.AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("sets protocol flags when multiple MCP sections present", func(t *testing.T) {
		middleware := Middleware{
			McpTools: map[string]*Operation{
				"get-weather": {Allow: &Allowance{Enabled: true}},
			},
			McpResources: map[string]*Operation{
				"file:///repo/*": {Allow: &Allowance{Enabled: true}},
			},
			McpPrompts: map[string]*Operation{
				"code-review": {Allow: &Allowance{Enabled: true}},
			},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Equal(t, apidef.JsonRPC20, api.JsonRpcVersion)
		assert.Equal(t, apidef.AppProtocolMCP, api.ApplicationProtocol)
		assert.True(t, api.IsMCP())
	})

	t.Run("does not set protocol flags when no MCP sections", func(t *testing.T) {
		middleware := Middleware{
			Global: &Global{
				SkipRateLimit: true,
			},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Empty(t, api.JsonRpcVersion)
		assert.False(t, api.IsMCP())
	})

	t.Run("does not set protocol flags when MCP sections are empty maps", func(t *testing.T) {
		middleware := Middleware{
			McpTools:     map[string]*Operation{},
			McpResources: map[string]*Operation{},
			McpPrompts:   map[string]*Operation{},
		}

		var api apidef.APIDefinition
		api.SetDisabledFlags()
		middleware.ExtractTo(&api)

		assert.Empty(t, api.JsonRpcVersion)
		assert.False(t, api.IsMCP())
	})
}

func TestMiddleware_Fill_MCP(t *testing.T) {
	t.Run("does not populate MCP fields when API is not MCP", func(t *testing.T) {
		api := apidef.APIDefinition{
			JsonRpcVersion:        "",
			ApplicationProtocol: "",
		}
		api.SetDisabledFlags()

		var middleware Middleware
		middleware.Fill(api)

		assert.Nil(t, middleware.McpTools)
		assert.Nil(t, middleware.McpResources)
		assert.Nil(t, middleware.McpPrompts)
	})

	t.Run("does not populate MCP fields when JsonRpcVersion is empty", func(t *testing.T) {
		api := apidef.APIDefinition{
			JsonRpcVersion:        "",
			ApplicationProtocol: apidef.AppProtocolMCP,
		}
		api.SetDisabledFlags()

		var middleware Middleware
		middleware.Fill(api)

		assert.Nil(t, middleware.McpTools)
		assert.Nil(t, middleware.McpResources)
		assert.Nil(t, middleware.McpPrompts)
	})

	t.Run("does not populate MCP fields when ApplicationProtocol is not MCP", func(t *testing.T) {
		api := apidef.APIDefinition{
			JsonRpcVersion:        apidef.JsonRPC20,
			ApplicationProtocol: "a2a",
		}
		api.SetDisabledFlags()

		var middleware Middleware
		middleware.Fill(api)

		assert.Nil(t, middleware.McpTools)
		assert.Nil(t, middleware.McpResources)
		assert.Nil(t, middleware.McpPrompts)
	})
}
