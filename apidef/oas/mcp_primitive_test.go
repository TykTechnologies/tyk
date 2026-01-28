package oas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMCPPrimitive_Embedding(t *testing.T) {
	t.Run("all Operation fields accessible", func(t *testing.T) {
		primitive := &MCPPrimitive{}

		primitive.Allow = &Allowance{Enabled: true}
		primitive.Block = &Allowance{Enabled: true}
		primitive.IgnoreAuthentication = &Allowance{Enabled: true}
		primitive.Internal = &Internal{Enabled: true}
		primitive.TransformRequestMethod = &TransformRequestMethod{Enabled: true}
		primitive.TransformRequestBody = &TransformBody{Enabled: true}
		primitive.TransformRequestHeaders = &TransformHeaders{Enabled: true}
		primitive.TransformResponseBody = &TransformBody{Enabled: true}
		primitive.TransformResponseHeaders = &TransformHeaders{Enabled: true}
		primitive.URLRewrite = &URLRewrite{Enabled: true}
		primitive.Cache = &CachePlugin{Enabled: true}
		primitive.EnforceTimeout = &EnforceTimeout{Enabled: true}
		primitive.CircuitBreaker = &CircuitBreaker{Enabled: true}
		primitive.RequestSizeLimit = &RequestSizeLimit{Enabled: true}
		primitive.RateLimit = &RateLimitEndpoint{Enabled: true, Rate: 100, Per: ReadableDuration(time.Minute)}
		primitive.ValidateRequest = &ValidateRequest{Enabled: true}
		primitive.MockResponse = &MockResponse{Enabled: true}
		primitive.VirtualEndpoint = &VirtualEndpoint{Enabled: true}
		primitive.PostPlugins = EndpointPostPlugins{{Enabled: true}}
		primitive.TrackEndpoint = &TrackEndpoint{Enabled: true}
		primitive.DoNotTrackEndpoint = &TrackEndpoint{Enabled: true}

		assert.NotNil(t, primitive.Allow)
		assert.NotNil(t, primitive.Block)
		assert.NotNil(t, primitive.RateLimit)
		assert.NotNil(t, primitive.Cache)
	})

	t.Run("field assignment works directly", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.Allow = &Allowance{Enabled: true}

		assert.NotNil(t, primitive.Allow)
		assert.True(t, primitive.Allow.Enabled)
	})
}

func TestMCPPrimitive_JSONMarshaling(t *testing.T) {
	t.Run("marshal and unmarshal with middleware", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.Allow = &Allowance{Enabled: true}
		primitive.RateLimit = &RateLimitEndpoint{
			Enabled: true,
			Rate:    100,
			Per:     ReadableDuration(time.Minute),
		}
		primitive.Cache = &CachePlugin{
			Enabled: true,
			Timeout: 60,
		}

		data, err := json.Marshal(primitive)
		require.NoError(t, err)

		var unmarshaled MCPPrimitive
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.NotNil(t, unmarshaled.Allow)
		assert.True(t, unmarshaled.Allow.Enabled)
		assert.NotNil(t, unmarshaled.RateLimit)
		assert.True(t, unmarshaled.RateLimit.Enabled)
		assert.Equal(t, 100, unmarshaled.RateLimit.Rate)
		assert.NotNil(t, unmarshaled.Cache)
		assert.True(t, unmarshaled.Cache.Enabled)
		assert.Equal(t, int64(60), unmarshaled.Cache.Timeout)
	})

	t.Run("marshal empty primitive produces minimal JSON", func(t *testing.T) {
		primitive := &MCPPrimitive{}

		data, err := json.Marshal(primitive)
		require.NoError(t, err)

		// Empty primitive should produce empty object or minimal JSON
		assert.Contains(t, string(data), "{")
	})

	t.Run("JSON format identical to Operation", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.Allow = &Allowance{Enabled: true}
		primitive.RateLimit = &RateLimitEndpoint{
			Enabled: true,
			Rate:    100,
			Per:     ReadableDuration(time.Minute),
		}

		operation := &Operation{}
		operation.Allow = &Allowance{Enabled: true}
		operation.RateLimit = &RateLimitEndpoint{
			Enabled: true,
			Rate:    100,
			Per:     ReadableDuration(time.Minute),
		}

		primitiveJSON, err := json.Marshal(primitive)
		require.NoError(t, err)

		operationJSON, err := json.Marshal(operation)
		require.NoError(t, err)

		// JSON output should be identical
		assert.JSONEq(t, string(operationJSON), string(primitiveJSON))
	})
}

func TestMCPPrimitives_MapOperations(t *testing.T) {
	t.Run("create and access primitives map", func(t *testing.T) {
		getWeather := &MCPPrimitive{}
		getWeather.Allow = &Allowance{Enabled: true}
		getWeather.RateLimit = &RateLimitEndpoint{
			Enabled: true,
			Rate:    100,
			Per:     ReadableDuration(time.Minute),
		}

		readFile := &MCPPrimitive{}
		readFile.RequestSizeLimit = &RequestSizeLimit{
			Enabled: true,
			Value:   1048576,
		}

		primitives := MCPPrimitives{
			"get-weather": getWeather,
			"read-file":   readFile,
		}

		assert.Len(t, primitives, 2)
		assert.NotNil(t, primitives["get-weather"])
		assert.NotNil(t, primitives["read-file"])

		// Access fields
		assert.True(t, primitives["get-weather"].Allow.Enabled)
		assert.Equal(t, 100, primitives["get-weather"].RateLimit.Rate)
		assert.Equal(t, int64(1048576), primitives["read-file"].RequestSizeLimit.Value)
	})

	t.Run("iterate over primitives map", func(t *testing.T) {
		tool1 := &MCPPrimitive{}
		tool1.Allow = &Allowance{Enabled: true}

		tool2 := &MCPPrimitive{}
		tool2.Block = &Allowance{Enabled: true}

		primitives := MCPPrimitives{
			"tool1": tool1,
			"tool2": tool2,
		}

		count := 0
		for name, primitive := range primitives {
			assert.NotEmpty(t, name)
			assert.NotNil(t, primitive)
			count++
		}
		assert.Equal(t, 2, count)
	})

	t.Run("marshal and unmarshal primitives map", func(t *testing.T) {
		getWeather := &MCPPrimitive{}
		getWeather.Allow = &Allowance{Enabled: true}
		getWeather.RateLimit = &RateLimitEndpoint{
			Enabled: true,
			Rate:    100,
			Per:     ReadableDuration(time.Minute),
		}

		primitives := MCPPrimitives{
			"get-weather": getWeather,
		}

		data, err := json.Marshal(primitives)
		require.NoError(t, err)

		var unmarshaled MCPPrimitives
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Len(t, unmarshaled, 1)
		assert.NotNil(t, unmarshaled["get-weather"])
		assert.True(t, unmarshaled["get-weather"].Allow.Enabled)
		assert.Equal(t, 100, unmarshaled["get-weather"].RateLimit.Rate)
	})

	t.Run("empty primitives map omitted in JSON", func(t *testing.T) {
		primitives := MCPPrimitives{}

		data, err := json.Marshal(primitives)
		require.NoError(t, err)

		// Empty map should serialize as {} or null
		result := string(data)
		assert.True(t, result == "{}" || result == "null")
	})

	t.Run("nil primitives map", func(t *testing.T) {
		var primitives MCPPrimitives = nil

		data, err := json.Marshal(primitives)
		require.NoError(t, err)

		assert.Equal(t, "null", string(data))
	})
}

func TestMCPPrimitive_DisabledMiddleware(t *testing.T) {
	t.Run("response transformation disabled for MCP", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.TransformResponseBody = &TransformBody{
			Enabled: true,
			Format:  apidef.RequestJSON,
			Body:    "transformed",
		}

		operation := &Operation{}
		operation.TransformResponseBody = &TransformBody{
			Enabled: true,
			Format:  apidef.RequestJSON,
			Body:    "transformed",
		}

		vemPath := "/mcp-tool:test"
		var mcpEP, opEP apidef.ExtendedPathsSet

		primitive.extractTransformResponseBodyTo(&mcpEP, vemPath, "POST")
		operation.extractTransformResponseBodyTo(&opEP, vemPath, "POST")

		assert.Empty(t, mcpEP.TransformResponse)
		assert.Len(t, opEP.TransformResponse, 1)
	})

	t.Run("request transformations still work", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.TransformRequestHeaders = &TransformHeaders{
			Enabled: true,
			Add:     Headers{{Name: "X-MCP", Value: "test"}},
		}
		primitive.TransformResponseBody = &TransformBody{Enabled: true}

		var ep apidef.ExtendedPathsSet
		primitive.extractTransformRequestHeadersTo(&ep, "/test", "POST")
		primitive.extractTransformResponseBodyTo(&ep, "/test", "POST")

		assert.Len(t, ep.TransformHeader, 1)
		primitive.ExtractToExtendedPaths(&ep, "/test", "POST")

		// Request headers transformation works
		assert.Len(t, ep.TransformHeader, 1)
		// Response body transformation is skipped for MCPPrimitive
		assert.Empty(t, ep.TransformResponse)
	})
}

func TestMCPPrimitive_EnsureNotBypassingOverride(t *testing.T) {
	t.Run("accepts valid primitive without panic", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.Allow = &Allowance{Enabled: true}

		assert.NotPanics(t, func() {
			ensureNotBypassingOverride(primitive)
		})
	})

	t.Run("accepts nil without panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ensureNotBypassingOverride(nil)
		})
	})

	t.Run("panics when given Operation directly", func(t *testing.T) {
		operation := &Operation{}
		operation.Allow = &Allowance{Enabled: true}

		assert.Panics(t, func() {
			ensureNotBypassingOverride(operation)
		})
	})

	t.Run("gateway usage pattern", func(t *testing.T) {
		getWeather := &MCPPrimitive{}
		getWeather.Allow = &Allowance{Enabled: true}

		primitives := MCPPrimitives{
			"get-weather": getWeather,
		}

		for _, prim := range primitives {
			assert.NotPanics(t, func() {
				ensureNotBypassingOverride(prim)
			})
		}
	})
}

func TestMCPPrimitive_NilSafety(t *testing.T) {
	t.Run("default fields are nil", func(t *testing.T) {
		primitive := &MCPPrimitive{}

		assert.Nil(t, primitive.Allow)
		assert.Nil(t, primitive.RateLimit)
		assert.Nil(t, primitive.Cache)
	})
}

func TestMCPPrimitive_MultipleMiddlewareScenarios(t *testing.T) {
	t.Run("tool with rate limit and cache", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.RateLimit = &RateLimitEndpoint{Enabled: true, Rate: 100, Per: ReadableDuration(time.Minute)}
		primitive.Cache = &CachePlugin{Enabled: true, Timeout: 60}
		primitive.Allow = &Allowance{Enabled: true}

		assert.Equal(t, 100, primitive.RateLimit.Rate)
		assert.Equal(t, int64(60), primitive.Cache.Timeout)
	})

	t.Run("resource with transforms and size limit", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.RequestSizeLimit = &RequestSizeLimit{Enabled: true, Value: 1048576}
		primitive.TransformRequestHeaders = &TransformHeaders{
			Enabled: true,
			Add:     Headers{{Name: "X-Resource-Type", Value: "file"}},
		}

		assert.Equal(t, int64(1048576), primitive.RequestSizeLimit.Value)
		assert.Len(t, primitive.TransformRequestHeaders.Add, 1)
	})
}
