package oas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/mcp"
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
	vemPath := mcp.ToolPrefix + "test"

	// Table-driven tests for all 7 disabled middleware.
	// Each test configures middleware on MCPPrimitive and verifies extraction is empty,
	// then configures the same middleware on Operation and verifies it works.
	testCases := []struct {
		name           string
		setupPrimitive func(p *MCPPrimitive)
		setupOperation func(o *Operation)
		// assertMCPEmpty checks that the extended paths set is empty for the disabled middleware.
		assertMCPEmpty func(t *testing.T, ep *apidef.ExtendedPathsSet)
		// assertOpPopulated checks that the extended paths set is populated for the Operation.
		assertOpPopulated func(t *testing.T, ep *apidef.ExtendedPathsSet)
	}{
		{
			name: "transformResponseBody",
			setupPrimitive: func(p *MCPPrimitive) {
				p.TransformResponseBody = &TransformBody{Enabled: true, Format: apidef.RequestJSON, Body: "transformed"}
			},
			setupOperation: func(o *Operation) {
				o.TransformResponseBody = &TransformBody{Enabled: true, Format: apidef.RequestJSON, Body: "transformed"}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.TransformResponse) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.TransformResponse, 1) },
		},
		{
			name: "transformRequestMethod",
			setupPrimitive: func(p *MCPPrimitive) {
				p.TransformRequestMethod = &TransformRequestMethod{Enabled: true, ToMethod: "GET"}
			},
			setupOperation: func(o *Operation) {
				o.TransformRequestMethod = &TransformRequestMethod{Enabled: true, ToMethod: "GET"}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.MethodTransforms) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.MethodTransforms, 1) },
		},
		{
			name: "internal",
			setupPrimitive: func(p *MCPPrimitive) {
				p.Internal = &Internal{Enabled: true}
			},
			setupOperation: func(o *Operation) {
				o.Internal = &Internal{Enabled: true}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.Internal) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.Internal, 1) },
		},
		{
			name: "urlRewrite",
			setupPrimitive: func(p *MCPPrimitive) {
				p.URLRewrite = &URLRewrite{Enabled: true, Pattern: ".*", RewriteTo: "/new"}
			},
			setupOperation: func(o *Operation) {
				o.URLRewrite = &URLRewrite{Enabled: true, Pattern: ".*", RewriteTo: "/new"}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.URLRewrite) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.URLRewrite, 1) },
		},
		{
			name: "cache",
			setupPrimitive: func(p *MCPPrimitive) {
				p.Cache = &CachePlugin{Enabled: true, Timeout: 60}
			},
			setupOperation: func(o *Operation) {
				o.Cache = &CachePlugin{Enabled: true, Timeout: 60}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.AdvanceCacheConfig) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.AdvanceCacheConfig, 1) },
		},
		{
			name: "validateRequest",
			setupPrimitive: func(p *MCPPrimitive) {
				p.ValidateRequest = &ValidateRequest{Enabled: true, ErrorResponseCode: 400}
			},
			setupOperation: func(o *Operation) {
				o.ValidateRequest = &ValidateRequest{Enabled: true, ErrorResponseCode: 400}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.ValidateRequest) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.ValidateRequest, 1) },
		},
		{
			name: "mockResponse",
			setupPrimitive: func(p *MCPPrimitive) {
				p.MockResponse = &MockResponse{Enabled: true, Code: 200, Body: `{"ok":true}`}
			},
			setupOperation: func(o *Operation) {
				o.MockResponse = &MockResponse{Enabled: true, Code: 200, Body: `{"ok":true}`}
			},
			assertMCPEmpty:    func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Empty(t, ep.MockResponse) },
			assertOpPopulated: func(t *testing.T, ep *apidef.ExtendedPathsSet) { assert.Len(t, ep.MockResponse, 1) },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name+" disabled for MCPPrimitive", func(t *testing.T) {
			primitive := &MCPPrimitive{}
			tc.setupPrimitive(primitive)

			var ep apidef.ExtendedPathsSet
			primitive.ExtractToExtendedPaths(&ep, vemPath, "POST")
			tc.assertMCPEmpty(t, &ep)
		})

		t.Run(tc.name+" works for Operation", func(t *testing.T) {
			operation := &Operation{}
			tc.setupOperation(operation)

			var ep apidef.ExtendedPathsSet
			operation.ExtractToExtendedPaths(&ep, vemPath, "POST")
			tc.assertOpPopulated(t, &ep)
		})
	}

	t.Run("allowed middleware still works for MCPPrimitive", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.TransformRequestHeaders = &TransformHeaders{
			Enabled: true,
			Add:     Headers{{Name: "X-MCP", Value: "test"}},
		}
		primitive.TransformResponseBody = &TransformBody{Enabled: true}
		primitive.RateLimit = &RateLimitEndpoint{Enabled: true, Rate: 100, Per: ReadableDuration(time.Minute)}

		var ep apidef.ExtendedPathsSet
		primitive.ExtractToExtendedPaths(&ep, vemPath, "POST")

		// Allowed middleware works
		assert.Len(t, ep.TransformHeader, 1)
		assert.Len(t, ep.RateLimit, 1)
		// Disabled middleware is skipped
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

func TestOperation_ExtractToExtendedPaths_ValidateRequestAndMockResponse(t *testing.T) {
	t.Run("extracts ValidateRequest middleware", func(t *testing.T) {
		op := &Operation{
			ValidateRequest: &ValidateRequest{
				Enabled:           true,
				ErrorResponseCode: 400,
			},
		}

		var ep apidef.ExtendedPathsSet
		op.ExtractToExtendedPaths(&ep, "/test", "POST")

		assert.Len(t, ep.ValidateRequest, 1)
		assert.Equal(t, "/test", ep.ValidateRequest[0].Path)
		assert.Equal(t, "POST", ep.ValidateRequest[0].Method)
		assert.True(t, ep.ValidateRequest[0].Enabled)
		assert.Equal(t, 400, ep.ValidateRequest[0].ErrorResponseCode)
	})

	t.Run("extracts MockResponse middleware", func(t *testing.T) {
		op := &Operation{
			MockResponse: &MockResponse{
				Enabled: true,
				Code:    200,
				Body:    `{"message": "mocked"}`,
				Headers: Headers{{Name: "X-Mock", Value: "true"}},
			},
		}

		var ep apidef.ExtendedPathsSet
		op.ExtractToExtendedPaths(&ep, "/test", "GET")

		assert.Len(t, ep.MockResponse, 1)
		assert.Equal(t, "/test", ep.MockResponse[0].Path)
		assert.Equal(t, "GET", ep.MockResponse[0].Method)
		assert.False(t, ep.MockResponse[0].Disabled)
		assert.Equal(t, 200, ep.MockResponse[0].Code)
		assert.Equal(t, `{"message": "mocked"}`, ep.MockResponse[0].Body)
		assert.Equal(t, "true", ep.MockResponse[0].Headers["X-Mock"])
	})

	t.Run("MCPPrimitive disables validateRequest and mockResponse extraction", func(t *testing.T) {
		primitive := &MCPPrimitive{}
		primitive.ValidateRequest = &ValidateRequest{
			Enabled:           true,
			ErrorResponseCode: 422,
		}
		primitive.MockResponse = &MockResponse{
			Enabled: true,
			Code:    404,
			Body:    `{"error": "not found"}`,
		}

		var ep apidef.ExtendedPathsSet
		primitive.ExtractToExtendedPaths(&ep, "/mcp/tool/test", "POST")

		// ValidateRequest and MockResponse are disabled for MCP primitives
		assert.Empty(t, ep.ValidateRequest)
		assert.Empty(t, ep.MockResponse)
	})
}
