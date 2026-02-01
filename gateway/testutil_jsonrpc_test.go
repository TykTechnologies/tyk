package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

// TestMockJSONRPCServer_BasicUsage demonstrates basic mock server usage.
func TestMockJSONRPCServer_BasicUsage(t *testing.T) {
	mockServer := NewMockJSONRPCServer()
	defer mockServer.Close()

	// Mock a tool response
	mockServer.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "The weather in London is sunny."},
		},
	})

	// Send a request to the mock server
	req := BuildToolsCallRequest("get-weather", map[string]any{"city": "London"}, 1)
	reqBody, _ := json.Marshal(req)

	resp, err := http.Post(mockServer.URL(), "application/json", &readCloser{data: reqBody})
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	rpcResp, err := ParseJSONRPCResponse(body)
	require.NoError(t, err)
	assert.Equal(t, "2.0", rpcResp.JSONRPC)
	assert.NotNil(t, rpcResp.Result)
	assert.Nil(t, rpcResp.Error)

	// Verify request was recorded
	received := mockServer.ReceivedRequests()
	require.Len(t, received, 1)
	assert.Equal(t, "tools/call", received[0].Method)
}

// TestMockJSONRPCServer_UnmockedMethodReturnsError tests that unmocked methods return errors.
func TestMockJSONRPCServer_UnmockedMethodReturnsError(t *testing.T) {
	mockServer := NewMockJSONRPCServer()
	defer mockServer.Close()

	req := BuildJSONRPCRequest("unknown/method", nil, 1)
	reqBody, _ := json.Marshal(req)

	resp, err := http.Post(mockServer.URL(), "application/json", &readCloser{data: reqBody})
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	rpcResp, err := ParseJSONRPCResponse(body)
	require.NoError(t, err)
	assert.Nil(t, rpcResp.Result)
	assert.NotNil(t, rpcResp.Error)
	assert.Equal(t, -32601, rpcResp.Error.Code) // Method not found
}

// TestMockJSONRPCServer_RequestRecording tests that requests are recorded.
func TestMockJSONRPCServer_RequestRecording(t *testing.T) {
	mockServer := NewMockJSONRPCServer()
	defer mockServer.Close()

	mockServer.SetErrorOnUnmocked(false)

	// Send multiple requests
	methods := []string{"tools/call", "resources/read", "tools/call"}
	for _, method := range methods {
		req := BuildJSONRPCRequest(method, map[string]any{"test": "value"}, 1)
		reqBody, _ := json.Marshal(req)
		resp, _ := http.Post(mockServer.URL(), "application/json", &readCloser{data: reqBody})
		resp.Body.Close()
	}

	// Verify all requests recorded
	received := mockServer.ReceivedRequests()
	require.Len(t, received, 3)

	// Filter by method
	toolCalls := mockServer.ReceivedRequestsForMethod("tools/call")
	require.Len(t, toolCalls, 2)
}

// TestMockJSONRPCServer_HeaderRecording tests that HTTP headers are recorded with requests.
func TestMockJSONRPCServer_HeaderRecording(t *testing.T) {
	mockServer := NewMockJSONRPCServer()
	defer mockServer.Close()

	mockServer.SetErrorOnUnmocked(false)

	// Send a request with custom headers
	req := BuildJSONRPCRequest("tools/call", map[string]any{"test": "value"}, 1)
	reqBody, _ := json.Marshal(req)

	httpReq, _ := http.NewRequest(http.MethodPost, mockServer.URL(), &readCloser{data: reqBody})
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Custom-Header", "TestValue")
	httpReq.Header.Set("Authorization", "Bearer test-token")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify headers were recorded
	received := mockServer.ReceivedRequests()
	require.Len(t, received, 1)
	assert.Equal(t, "application/json", received[0].Headers.Get("Content-Type"))
	assert.Equal(t, "TestValue", received[0].Headers.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer test-token", received[0].Headers.Get("Authorization"))
}

// TestMockJSONRPCServer_WithGateway demonstrates using the mock server with Tyk Gateway.
func TestMockJSONRPCServer_WithGateway(t *testing.T) {
	// Create mock upstream JSON-RPC server
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	// Configure mock responses for MCP tools
	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Mock response from upstream"},
		},
	})

	// Start Tyk Gateway test
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS API definition pointing to mock server
	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "MCP Test API",
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		},
	}

	tykExt := &oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "MCP Mock Test",
			ID:   randStringBytes(8),
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{
			URL: mockUpstream.URL(),
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/mcp-mock",
				Strip: true,
			},
		},
		Middleware: &oas.Middleware{
			McpTools: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-mock"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	// Send JSON-RPC request through gateway
	payload := BuildToolsCallRequest("weather.getForecast", map[string]any{"city": "London"}, 1)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp-mock",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Verify mock server received the request
	received := mockUpstream.ReceivedRequests()
	require.Len(t, received, 1, "Mock server should have received 1 request")
	assert.Equal(t, "tools/call", received[0].Method)
}

// TestJSONRPC_RateLimiting_WithMockUpstream tests rate limiting with mock upstream.
func TestJSONRPC_RateLimiting_WithMockUpstream(t *testing.T) {
	// Create mock upstream
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-rl",
		Strip: true,
	}
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"rate-limited-tool": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    2, // 2 requests per second
						Per:     oas.ReadableDuration(time.Second),
					},
				},
			},
			"unlimited-tool": &oas.MCPPrimitive{},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-rl"
	def.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	rateLimitedPayload := BuildToolsCallRequest("rate-limited-tool", nil, 1)
	unlimitedPayload := BuildToolsCallRequest("unlimited-tool", nil, 2)

	// First two requests should succeed
	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/mcp-rl", Data: rateLimitedPayload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-rl", Data: rateLimitedPayload, Code: http.StatusOK},
		// Third request should be rate limited
		{Method: http.MethodPost, Path: "/mcp-rl", Data: rateLimitedPayload, Code: http.StatusTooManyRequests},
		// Different tool should still work
		{Method: http.MethodPost, Path: "/mcp-rl", Data: unlimitedPayload, Code: http.StatusOK},
	}...)
}

// TestJSONRPC_ACL_WithMockUpstream tests ACL enforcement with mock upstream.
func TestJSONRPC_ACL_WithMockUpstream(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-acl",
		Strip: true,
	}
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"allowed-tool": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			// blocked-tool is not in the list, so it will be blocked when allowlist is enabled
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-acl"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	allowedPayload := BuildToolsCallRequest("allowed-tool", nil, 1)
	blockedPayload := BuildToolsCallRequest("blocked-tool", nil, 2)
	unknownPayload := BuildToolsCallRequest("unknown-tool", nil, 3)

	_, _ = ts.Run(t, []test.TestCase{
		// Allowed tool should work
		{Method: http.MethodPost, Path: "/mcp-acl", Data: allowedPayload, Code: http.StatusOK},
		// Blocked tool should be forbidden
		{Method: http.MethodPost, Path: "/mcp-acl", Data: blockedPayload, Code: http.StatusForbidden},
		// Unknown tool should be forbidden when allowlist is active
		{Method: http.MethodPost, Path: "/mcp-acl", Data: unknownPayload, Code: http.StatusForbidden},
	}...)

	// Verify only allowed tool reached upstream
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 1, "Only allowed tool should reach upstream")
}

// TestJSONRPC_ResourceACL_WithMockUpstream tests ACL enforcement for resources.
func TestJSONRPC_ResourceACL_WithMockUpstream(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("resources/read", map[string]any{
		"contents": []map[string]any{
			{"uri": "file:///data/config.json", "text": "{}"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-resource-acl",
		Strip: true,
	}
	tykExt.Middleware = &oas.Middleware{
		McpResources: oas.MCPPrimitives{
			"file:///data/*": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-resource-acl"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	allowedPayload := BuildResourcesReadRequest("file:///data/config.json", 1)
	blockedPayload := BuildResourcesReadRequest("file:///secrets/api-key.txt", 2)

	_, _ = ts.Run(t, []test.TestCase{
		// Allowed resource path should work
		{Method: http.MethodPost, Path: "/mcp-resource-acl", Data: allowedPayload, Code: http.StatusOK},
		// Blocked resource path should be forbidden
		{Method: http.MethodPost, Path: "/mcp-resource-acl", Data: blockedPayload, Code: http.StatusForbidden},
	}...)
}

// TestJSONRPC_DynamicHandler tests using dynamic handlers for assertions.
func TestJSONRPC_DynamicHandler(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	// Track received arguments for assertion
	var receivedArgs map[string]any
	mockUpstream.MockMethodHandler("tools/call", func(_ *testing.T, method string, params json.RawMessage) (any, int, string) {
		// Parse params to extract arguments
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		json.Unmarshal(params, &p)
		receivedArgs = p.Arguments

		return map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "Processed: " + p.Name},
			},
		}, 0, ""
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-handler",
		Strip: true,
	}
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"test-tool": &oas.MCPPrimitive{},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-handler"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	payload := BuildToolsCallRequest("test-tool", map[string]any{
		"city":    "London",
		"country": "UK",
	}, 1)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp-handler",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Verify arguments were received correctly
	assert.Equal(t, "London", receivedArgs["city"])
	assert.Equal(t, "UK", receivedArgs["country"])
}

// readCloser is a helper for creating io.ReadCloser from byte slice
type readCloser struct {
	data []byte
	pos  int
}

func (r *readCloser) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *readCloser) Close() error {
	return nil
}

// TestJSONRPC_MethodLevelAllowList tests that method-level allow lists
// correctly proxy allowed tools and reject disallowed tools.
// Acceptance Criteria #1: When an allow list is configured at the method level,
// only requests for the allowed tool are proxied, and requests for other tools are rejected.
func TestJSONRPC_MethodLevelAllowList(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-method-acl",
		Strip: true,
	}
	// Configure method-level allow list: only "calculator" tool is allowed
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"calculator": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-method-acl"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	// Test 1: Allowed tool should succeed (HTTP 200)
	allowedPayload := BuildToolsCallRequest("calculator", map[string]any{"expression": "2+2"}, 1)
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp-method-acl",
		Data:   allowedPayload,
		Code:   http.StatusOK,
	})

	// Test 2: Disallowed tool should be rejected (HTTP 403)
	disallowedPayload := BuildToolsCallRequest("weather_reporter", map[string]any{"city": "London"}, 2)
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp-method-acl",
		Data:   disallowedPayload,
		Code:   http.StatusForbidden,
	})

	// Verify only the allowed tool reached upstream
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 1, "Only the allowed tool (calculator) should reach upstream")

	// Verify the request params contain the calculator tool
	var params struct {
		Name string `json:"name"`
	}
	json.Unmarshal(received[0].Params, &params)
	assert.Equal(t, "calculator", params.Name)
}

// TestJSONRPC_ToolLevelAllowList tests that tool-level allow lists
// correctly proxy allowed tools and reject disallowed tools.
// Acceptance Criteria #2: When an allow list is configured at the tool level,
// only requests for the specifically allowed tools are proxied, and others are rejected.
func TestJSONRPC_ToolLevelAllowList(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-tool-acl",
		Strip: true,
	}
	// Configure tool-level allow list with multiple specific tools
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get-weather": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			"get-temperature": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			"get-stock-price": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-tool-acl"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	// Test: Each allowed tool should succeed
	weatherPayload := BuildToolsCallRequest("get-weather", nil, 1)
	temperaturePayload := BuildToolsCallRequest("get-temperature", nil, 2)
	stockPayload := BuildToolsCallRequest("get-stock-price", nil, 3)
	disallowedPayload := BuildToolsCallRequest("delete-user", nil, 4)

	_, _ = ts.Run(t, []test.TestCase{
		// All allowed tools should work
		{Method: http.MethodPost, Path: "/mcp-tool-acl", Data: weatherPayload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-tool-acl", Data: temperaturePayload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-tool-acl", Data: stockPayload, Code: http.StatusOK},
		// Disallowed tool should be rejected
		{Method: http.MethodPost, Path: "/mcp-tool-acl", Data: disallowedPayload, Code: http.StatusForbidden},
	}...)

	// Verify only allowed tools reached upstream (3 requests)
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 3, "Only the three allowed tools should reach upstream")
}

// TestJSONRPC_MethodLevelRateLimiting tests that rate limits configured at the method level
// are correctly applied.
// Acceptance Criteria #3: Rate limits configured at the method level (for tool calls) are correctly applied.
func TestJSONRPC_MethodLevelRateLimiting(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-method-rl",
		Strip: true,
	}
	// Configure rate limit on a specific tool: 3 requests per 10 seconds
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"limited-tool": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    3,
						Per:     oas.ReadableDuration(10 * time.Second),
					},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-method-rl"
	def.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	payload := BuildToolsCallRequest("limited-tool", nil, 1)

	// First 3 requests should succeed (within rate limit)
	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/mcp-method-rl", Data: payload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-method-rl", Data: payload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-method-rl", Data: payload, Code: http.StatusOK},
		// Fourth request should be rate limited (HTTP 429)
		{Method: http.MethodPost, Path: "/mcp-method-rl", Data: payload, Code: http.StatusTooManyRequests},
	}...)

	// Verify only 3 requests reached upstream
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 3, "Only 3 requests should reach upstream before rate limiting")
}

// TestJSONRPC_ToolLevelIndependentRateLimiting tests that rate limits are applied independently
// for different tools.
// Acceptance Criteria #4: Rate limits are correctly applied for different configured tools independently.
func TestJSONRPC_ToolLevelIndependentRateLimiting(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-tool-rl",
		Strip: true,
	}
	// Configure different rate limits for two tools
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"tool-a": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    1, // Only 1 request allowed
						Per:     oas.ReadableDuration(10 * time.Second),
					},
				},
			},
			"tool-b": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    5, // 5 requests allowed
						Per:     oas.ReadableDuration(10 * time.Second),
					},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-tool-rl"
	def.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	toolAPayload := BuildToolsCallRequest("tool-a", nil, 1)
	toolBPayload := BuildToolsCallRequest("tool-b", nil, 2)

	// Test sequence:
	// 1. First request to tool-a should succeed
	// 2. Second request to tool-a should be rate limited
	// 3. Requests to tool-b should still succeed (independent rate limit)
	_, _ = ts.Run(t, []test.TestCase{
		// tool-a: first request succeeds
		{Method: http.MethodPost, Path: "/mcp-tool-rl", Data: toolAPayload, Code: http.StatusOK},
		// tool-a: second request gets rate limited
		{Method: http.MethodPost, Path: "/mcp-tool-rl", Data: toolAPayload, Code: http.StatusTooManyRequests},
		// tool-b: should still work (independent rate limit)
		{Method: http.MethodPost, Path: "/mcp-tool-rl", Data: toolBPayload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-tool-rl", Data: toolBPayload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp-tool-rl", Data: toolBPayload, Code: http.StatusOK},
	}...)

	// Verify the correct number of requests reached upstream
	// tool-a: 1 request, tool-b: 3 requests = 4 total
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 4, "4 requests should reach upstream (1 for tool-a, 3 for tool-b)")
}

// TestJSONRPC_CombinedHeaderTransformations tests that request transformation headers
// defined at both the method and tool level are combined and sent to the upstream.
// Acceptance Criteria #5: When request transformation headers are defined at both the method
// and tool level, the upstream receives the combined set of headers.
func TestJSONRPC_CombinedHeaderTransformations(t *testing.T) {
	mockUpstream := NewMockJSONRPCServer()
	defer mockUpstream.Close()

	mockUpstream.MockMethod("tools/call", map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Success"},
		},
	})

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Upstream.URL = mockUpstream.URL()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp-headers",
		Strip: true,
	}
	// Configure headers at the tool level
	// Note: MCP primitives support transformRequestHeaders for adding headers
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"header-test-tool": &oas.MCPPrimitive{
				Operation: oas.Operation{
					TransformRequestHeaders: &oas.TransformHeaders{
						Enabled: true,
						Add: oas.Headers{
							{Name: "X-Tool-Header", Value: "ToolValue"},
							{Name: "X-Custom-Header", Value: "CustomValue"},
						},
					},
				},
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp-headers"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	payload := BuildToolsCallRequest("header-test-tool", map[string]any{"param": "value"}, 1)

	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/mcp-headers",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Verify the mock upstream received the transformed headers
	received := mockUpstream.ReceivedRequestsForMethod("tools/call")
	require.Len(t, received, 1, "One request should reach upstream")

	// Check that the custom headers were added
	headers := received[0].Headers
	assert.Equal(t, "ToolValue", headers.Get("X-Tool-Header"), "X-Tool-Header should be present")
	assert.Equal(t, "CustomValue", headers.Get("X-Custom-Header"), "X-Custom-Header should be present")
}

// TestBuildHelpers tests the request building helpers.
func TestBuildHelpers(t *testing.T) {
	t.Run("BuildJSONRPCRequest", func(t *testing.T) {
		req := BuildJSONRPCRequest("test/method", map[string]any{"key": "value"}, 42)
		assert.Equal(t, "2.0", req["jsonrpc"])
		assert.Equal(t, "test/method", req["method"])
		assert.Equal(t, 42, req["id"])
		params := req["params"].(map[string]any)
		assert.Equal(t, "value", params["key"])
	})

	t.Run("BuildToolsCallRequest", func(t *testing.T) {
		req := BuildToolsCallRequest("get-weather", map[string]any{"city": "London"}, 1)
		assert.Equal(t, "tools/call", req["method"])
		params := req["params"].(map[string]any)
		assert.Equal(t, "get-weather", params["name"])
		args := params["arguments"].(map[string]any)
		assert.Equal(t, "London", args["city"])
	})

	t.Run("BuildResourcesReadRequest", func(t *testing.T) {
		req := BuildResourcesReadRequest("file:///data/config.json", 1)
		assert.Equal(t, "resources/read", req["method"])
		params := req["params"].(map[string]any)
		assert.Equal(t, "file:///data/config.json", params["uri"])
	})

	t.Run("BuildPromptsGetRequest", func(t *testing.T) {
		req := BuildPromptsGetRequest("summarize", map[string]any{"text": "hello"}, 1)
		assert.Equal(t, "prompts/get", req["method"])
		params := req["params"].(map[string]any)
		assert.Equal(t, "summarize", params["name"])
		args := params["arguments"].(map[string]any)
		assert.Equal(t, "hello", args["text"])
	})
}
