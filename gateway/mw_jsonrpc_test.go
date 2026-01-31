package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/test"
)

func TestJSONRPCMiddleware_EnabledForSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     *APISpec
		expected bool
	}{
		{
			name: "enabled for MCP with JSON-RPC 2.0",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: apidef.AppProtocolMCP,
					JsonRpcVersion:      apidef.JsonRPC20,
				},
			},
			expected: true,
		},
		{
			name: "disabled for non-MCP API",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: "",
					JsonRpcVersion:      apidef.JsonRPC20,
				},
			},
			expected: false,
		},
		{
			name: "disabled for MCP without JSON-RPC 2.0",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: apidef.AppProtocolMCP,
					JsonRpcVersion:      "1.0",
				},
			},
			expected: false,
		},
		{
			name: "disabled for non-MCP without JSON-RPC",
			spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					ApplicationProtocol: "",
					JsonRpcVersion:      "",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &JSONRPCMiddleware{
				BaseMiddleware: &BaseMiddleware{Spec: tt.spec},
			}
			assert.Equal(t, tt.expected, m.EnabledForSpec())
		})
	}
}

func TestJSONRPCMiddleware_ProcessRequest_NonPostPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCMiddleware_ProcessRequest_NonJSONPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("plain text")))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestJSONRPCMiddleware_ProcessRequest_InvalidJSON(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, mcp.JSONRPCParseError, resp.Error.Code)
	assert.Equal(t, mcp.ErrMsgParseError, resp.Error.Message)
}

func TestJSONRPCMiddleware_ProcessRequest_InvalidRequest(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	tests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{
			name:    "missing jsonrpc version",
			payload: map[string]interface{}{"method": "tools/call", "id": 1},
		},
		{
			name:    "wrong jsonrpc version",
			payload: map[string]interface{}{"jsonrpc": "1.0", "method": "tools/call", "id": 1},
		},
		{
			name:    "missing method",
			payload: map[string]interface{}{"jsonrpc": "2.0", "id": 1},
		},
		{
			name:    "empty method",
			payload: map[string]interface{}{"jsonrpc": "2.0", "method": "", "id": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.payload)
			require.NoError(t, err)
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

			var resp JSONRPCErrorResponse
			err = json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)
			assert.Equal(t, mcp.JSONRPCInvalidRequest, resp.Error.Code)
		})
	}
}

func TestJSONRPCMiddleware_ProcessRequest_ToolsCall_RoutesToVEM(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:get-weather": "/mcp-tool:get-weather",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "get-weather", "arguments": map[string]string{"city": "London"}},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code, "Should return StatusOK to let DummyProxyHandler handle redirect")

	// NEW: Sequential routing checks
	// 1. Check redirect URL points to operation VEM (first stage)
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL, "Should have redirect URL")
	assert.Equal(t, "tyk", redirectURL.Scheme)
	assert.Equal(t, "self", redirectURL.Host)
	assert.Equal(t, "/json-rpc-method:tools/call", redirectURL.Path, "Should redirect to operation VEM first")

	// 2. Check routing state has NextVEM set to tool VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state, "Routing state should be set")
	assert.Equal(t, "tools/call", state.Method)
	assert.Equal(t, "/mcp-tool:get-weather", state.NextVEM, "NextVEM should be tool VEM")
	assert.Equal(t, []string{"/json-rpc-method:tools/call", "/mcp-tool:get-weather"}, state.VEMChain)

	assert.True(t, httpctx.IsJsonRPCRouting(r))
}

func TestJSONRPCMiddleware_ProcessRequest_ToolsCall_NotFound(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "unknown-tool"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/", r.URL.Path)
	assert.False(t, httpctx.IsJsonRPCRouting(r))
	assert.Nil(t, httpctx.GetJSONRPCRequest(r))
	assert.Equal(t, 0, w.Body.Len())
}

func TestJSONRPCMiddleware_ProcessRequest_ToolsCall_NotFound_WithAllowList(t *testing.T) {
	// When MCPAllowListEnabled is true, unknown tools are routed to a VEM path
	// that will be caught by the catch-all BlackList middleware.
	// The blocking happens at the BlackList/VersionCheck middleware level, not here.
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:get-weather": "/mcp-tool:get-weather",
		},
		MCPAllowListEnabled: true,
		JSONRPCRouter:       mcp.NewRouter(true),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "unknown-tool"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code, "Should return StatusOK to let DummyProxyHandler handle redirect")

	// NEW: Sequential routing checks
	// Request is routed to operation VEM first, then continuation middleware will route to tool VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL, "Should have redirect URL")
	assert.Equal(t, "tyk", redirectURL.Scheme)
	assert.Equal(t, "self", redirectURL.Host)
	assert.Equal(t, "/json-rpc-method:tools/call", redirectURL.Path, "Should redirect to operation VEM first")

	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state, "Routing state should be set")
	assert.Equal(t, "/mcp-tool:unknown-tool", state.NextVEM, "NextVEM should be unknown tool VEM for blocking")

	assert.True(t, httpctx.IsJsonRPCRouting(r))
	assert.Equal(t, 0, w.Body.Len(), "no error response should be written by middleware")
}

func TestJSONRPCMiddleware_ProcessRequest_AllowListBehavior(t *testing.T) {
	// Scenario: MCP API with 2 registered VEMs and 1 unregistered primitive.
	// - "tool-with-allow": registered with Allow enabled
	// - "tool-without-allow": registered but without Allow
	// - "unregistered-tool": not registered
	//
	// When MCPAllowListEnabled is true (because at least one primitive has Allow):
	// - Registered primitives route to their VEMs (middleware chain decides access)
	// - Unregistered primitives route to catch-all VEM path (blocked by catch-all BlackList)

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:tool-with-allow":    "/mcp-tool:tool-with-allow",
			"tool:tool-without-allow": "/mcp-tool:tool-without-allow",
			// "unregistered-tool" is intentionally NOT in the map
		},
		MCPAllowListEnabled: true, // Set because at least one primitive has Allow enabled
		JSONRPCRouter:       mcp.NewRouter(true),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	tests := []struct {
		name        string
		toolName    string
		expectedVEM string // expected VEM path (always routed when MCPAllowListEnabled)
	}{
		{
			name:        "registered tool with allow - routes to VEM",
			toolName:    "tool-with-allow",
			expectedVEM: "/mcp-tool:tool-with-allow",
		},
		{
			name:        "registered tool without allow - routes to VEM",
			toolName:    "tool-without-allow",
			expectedVEM: "/mcp-tool:tool-without-allow",
		},
		{
			name:        "unregistered tool - routes to catch-all VEM",
			toolName:    "unregistered-tool",
			expectedVEM: "/mcp-tool:unregistered-tool", // Will be caught by catch-all BlackList VEM
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"jsonrpc": "2.0",
				"method":  "tools/call",
				"params":  map[string]any{"name": tt.toolName},
				"id":      1,
			}
			body, err := json.Marshal(payload)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck

			// NEW: Sequential routing checks
			// All requests should be routed to operation VEM first when MCPAllowListEnabled
			redirectURL := ctxGetURLRewriteTarget(r)
			require.NotNil(t, redirectURL, "Should have redirect URL")
			assert.Equal(t, "/json-rpc-method:tools/call", redirectURL.Path, "Should redirect to operation VEM first")

			state := httpctx.GetJSONRPCRoutingState(r)
			require.NotNil(t, state, "Routing state should be set")
			assert.Equal(t, tt.expectedVEM, state.NextVEM, "NextVEM should be tool VEM")
			assert.True(t, httpctx.IsJsonRPCRouting(r), "JSON-RPC routing flag should be set")
			assert.Equal(t, 0, w.Body.Len(), "no error response should be written")
		})
	}
}

func TestJSONRPCMiddleware_ProcessRequest_ResourcesRead_ExactMatch(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///config.json": "/mcp-resource:file:///config.json",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///config.json"},
		"id":      "req-1",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM (first stage)
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL, "Should have redirect URL")
	assert.Equal(t, "/json-rpc-method:resources/read", redirectURL.Path)

	// Check routing state has NextVEM set to resource VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state, "Routing state should be set")
	assert.Equal(t, "/mcp-resource:file:///config.json", state.NextVEM, "NextVEM should be resource VEM")
}

func TestJSONRPCMiddleware_ProcessRequest_ResourcesRead_WildcardMatch(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///repo/*": "/mcp-resource:file:///repo/*",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///repo/README.md"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL)
	assert.Equal(t, "/json-rpc-method:resources/read", redirectURL.Path)

	// Check routing state has NextVEM set to resource VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state)
	assert.Equal(t, "/mcp-resource:file:///repo/*", state.NextVEM)
}

func TestJSONRPCMiddleware_ProcessRequest_ResourcesRead_ExactBeatsWildcard(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///repo/*":           "/mcp-resource:file:///repo/*",
			"resource:file:///repo/README.md":   "/mcp-resource:file:///repo/README.md",
			"resource:file:///repo/README.txt":  "/mcp-resource:file:///repo/README.txt",
			"resource:file:///repo/README.mdx":  "/mcp-resource:file:///repo/README.mdx",
			"resource:file:///repo/README.json": "/mcp-resource:file:///repo/README.json",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///repo/README.md"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL)
	assert.Equal(t, "/json-rpc-method:resources/read", redirectURL.Path)

	// Check routing state has NextVEM set to exact match resource VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state)
	assert.Equal(t, "/mcp-resource:file:///repo/README.md", state.NextVEM)
}

func TestJSONRPCMiddleware_ProcessRequest_ResourcesRead_MostSpecificWildcard(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///repo/*":      "/mcp-resource:file:///repo/*",
			"resource:file:///repo/docs/*": "/mcp-resource:file:///repo/docs/*",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///repo/docs/README.md"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL)
	assert.Equal(t, "/json-rpc-method:resources/read", redirectURL.Path)

	// Check routing state has NextVEM set to most specific wildcard resource VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state)
	assert.Equal(t, "/mcp-resource:file:///repo/docs/*", state.NextVEM)
}

func TestJSONRPCMiddleware_ProcessRequest_PromptsGet(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"prompt:code-review": "/mcp-prompt:code-review",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  map[string]interface{}{"name": "code-review"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL)
	assert.Equal(t, "/json-rpc-method:prompts/get", redirectURL.Path)

	// Check routing state has NextVEM set to prompt VEM
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state)
	assert.Equal(t, "/mcp-prompt:code-review", state.NextVEM)
}

func TestJSONRPCMiddleware_ProcessRequest_OperationVEM(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"operation:tools/list": "/json-rpc-method:tools-list",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)

	// Check redirect URL points to operation VEM
	redirectURL := ctxGetURLRewriteTarget(r)
	require.NotNil(t, redirectURL)
	// When an operation VEM is registered, use the registered path
	assert.Equal(t, "/json-rpc-method:tools-list", redirectURL.Path)

	// Check routing state - discovery methods have NO NextVEM (1-stage routing)
	state := httpctx.GetJSONRPCRoutingState(r)
	require.NotNil(t, state)
	assert.Equal(t, "", state.NextVEM, "Discovery methods should have empty NextVEM (1-stage routing)")
}

func TestJSONRPCMiddleware_ProcessRequest_DiscoveryPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{}, // No configured VEMs
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// Discovery operations should pass through when no VEM is configured
	methods := []string{"tools/list", "resources/list", "prompts/list", "initialize", "ping"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			payload := map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  method,
				"id":      1,
			}
			body, err := json.Marshal(payload)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/original-path", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			err, code := m.ProcessRequest(w, r, nil)
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, code)
			// Path should not be rewritten for passthrough
			assert.Equal(t, "/original-path", r.URL.Path)
			assert.False(t, httpctx.IsJsonRPCRouting(r))
		})
	}
}

func TestJSONRPCMiddleware_ProcessRequest_NotificationsPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/progress",
		// No ID - notifications don't have IDs
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/", r.URL.Path)
	assert.False(t, httpctx.IsJsonRPCRouting(r))
	assert.Nil(t, httpctx.GetJSONRPCRequest(r))
	assert.Equal(t, 0, w.Body.Len())
}

func TestJSONRPCMiddleware_ProcessRequest_UnmatchedMethodPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "custom/op",
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/original", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/original", r.URL.Path)
	assert.False(t, httpctx.IsJsonRPCRouting(r))
	assert.Nil(t, httpctx.GetJSONRPCRequest(r))
	assert.Equal(t, 0, w.Body.Len())
}

func TestJSONRPCMiddleware_ProcessRequest_BodyRestored(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:test": "/mcp-tool:test",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	originalPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "test", "arguments": map[string]string{"key": "value"}},
		"id":      1,
	}
	originalBody, err := json.Marshal(originalPayload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // testing body restoration

	// Body should be restored for upstream
	restoredBody, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, restoredBody)
}

func TestJSONRPCMiddleware_ProcessRequest_NullID(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// JSON with null ID and invalid params
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{}},"id":null}`)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCInvalidParams, resp.Error.Code)
	assert.Nil(t, resp.ID) // ID should be preserved as null
}

func TestJSONRPCMiddleware_MapJSONRPCErrorToHTTP(t *testing.T) {
	m := &JSONRPCMiddleware{}

	tests := []struct {
		code     int
		expected int
	}{
		{mcp.JSONRPCParseError, http.StatusBadRequest},
		{mcp.JSONRPCInvalidRequest, http.StatusBadRequest},
		{mcp.JSONRPCMethodNotFound, http.StatusNotFound},
		{mcp.JSONRPCInvalidParams, http.StatusBadRequest},
		{mcp.JSONRPCInternalError, http.StatusInternalServerError},
		{-32000, http.StatusForbidden},           // Server error range
		{-32050, http.StatusForbidden},           // Server error range
		{-32099, http.StatusForbidden},           // Server error range
		{-99999, http.StatusInternalServerError}, // Unknown error
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := m.mapJSONRPCErrorToHTTP(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJSONRPCMiddleware_ResourcesSubscribe(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:events://*": "/mcp-resource:events://*",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/subscribe",
		"params":  map[string]interface{}{"uri": "events://updates"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/original-path", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	// resources/subscribe now passthroughs to upstream by default
	assert.Equal(t, "/original-path", r.URL.Path)
	assert.False(t, httpctx.IsJsonRPCRouting(r))
}

func TestJSONRPCMiddleware_ResourcesUnsubscribe(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:events://topic": "/mcp-resource:events://topic",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/unsubscribe",
		"params":  map[string]interface{}{"uri": "events://topic"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/original-path", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	// resources/unsubscribe now passthroughs to upstream by default
	assert.Equal(t, "/original-path", r.URL.Path)
	assert.False(t, httpctx.IsJsonRPCRouting(r))
}

func TestJSONRPCMiddleware_ToolsCall_MissingParamsName(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:test": "/mcp-tool:test",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// Missing params.name
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"arguments": map[string]string{}},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

	var resp JSONRPCErrorResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCInvalidParams, resp.Error.Code)
}

func TestJSONRPCMiddleware_ToolsCall_NonStringName_InvalidParams(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:test": "/mcp-tool:test",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": 123},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

	var resp JSONRPCErrorResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCInvalidParams, resp.Error.Code)
}

func TestJSONRPCMiddleware_ResourcesRead_MissingParamsURI_InvalidParams(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///repo/*": "/mcp-resource:file:///repo/*",
		},
		JSONRPCRouter: mcp.NewRouter(false),
	}

	m := &JSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"name": "missing-uri"},
		"id":      1,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil) //nolint:errcheck // error handled via JSON-RPC response

	var resp JSONRPCErrorResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCInvalidParams, resp.Error.Code)
}

func TestJSONRPCMiddleware_AllowListEnforcedOnVEM(t *testing.T) {
	// Scenario: MCP API with 2 registered tools and 1 unregistered.
	// - "tool-allowed": has Allow.Enabled = true
	// - "tool-not-allowed": registered but no Allow
	// - "unregistered-tool": not registered at all
	//
	// Expected behavior:
	// - tool-allowed: routed to VEM, Allow middleware permits → 200 OK
	// - tool-not-allowed: routed to VEM, but no Allow entry → blocked by Allow middleware
	// - unregistered-tool: rejected at JSON-RPC middleware with "Method not found"

	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp",
		Strip: false,
	}
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"tool-allowed": &oas.MCPPrimitive{
				Operation: oas.Operation{
					Allow: &oas.Allowance{Enabled: true},
				},
			},
			"tool-not-allowed": &oas.MCPPrimitive{
				// No Allow configured - should be blocked when allow list is active
			},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	loaded := ts.Gw.getApiSpec(def.APIID)
	require.NotNil(t, loaded)
	assert.True(t, loaded.IsMCP())
	assert.True(t, loaded.MCPAllowListEnabled, "MCPAllowListEnabled should be true when any primitive has Allow")

	// Debug: Print rxPaths to understand what specs are being generated
	for versionName, rxPaths := range loaded.RxPaths {
		t.Logf("Version %s has %d rxPaths, WhiteListEnabled: %v", versionName, len(rxPaths), loaded.WhiteListEnabled[versionName])
		for i, spec := range rxPaths {
			t.Logf("  [%d] Status=%d, Path regex=%v", i, spec.Status, spec.spec)
			if spec.Status == WhiteList {
				t.Logf("       WhiteList: Path=%s, Method=%s", spec.Whitelist.Path, spec.Whitelist.Method)
			}
			if spec.Status == BlackList {
				t.Logf("       BlackList: Path=%s, Method=%s", spec.Blacklist.Path, spec.Blacklist.Method)
			}
			if spec.Status == Internal {
				t.Logf("       Internal: Path=%s, Method=%s", spec.Internal.Path, spec.Internal.Method)
			}
		}
	}

	allowedPayload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]any{"name": "tool-allowed"},
		"id":      1,
	}
	notAllowedPayload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]any{"name": "tool-not-allowed"},
		"id":      2,
	}
	unregisteredPayload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]any{"name": "unregistered-tool"},
		"id":      3,
	}

	_, _ = ts.Run(t, []test.TestCase{
		// tool-allowed: should pass (has Allow.Enabled, gets Internal + WhiteList)
		{Method: http.MethodPost, Path: "/mcp", Data: allowedPayload, Code: http.StatusOK},
		// tool-not-allowed: blocked by catch-all BlackList (no Internal entry when allowList enabled)
		{Method: http.MethodPost, Path: "/mcp", Data: notAllowedPayload, Code: http.StatusForbidden},
		// unregistered-tool: blocked by catch-all BlackList (routed via buildUnregisteredVEMPath)
		{Method: http.MethodPost, Path: "/mcp", Data: unregisteredPayload, Code: http.StatusForbidden},
	}...)
}

func TestJSONRPCMiddleware_RateLimitEnforcedOnVEM(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	oasAPI := getSampleOASAPI()
	tykExt := oasAPI.GetTykExtension()
	tykExt.Server.ListenPath = oas.ListenPath{
		Value: "/mcp",
		Strip: false,
	}
	tykExt.Middleware = &oas.Middleware{
		McpTools: oas.MCPPrimitives{
			"get-weather": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    1,
						Per:     oas.ReadableDuration(time.Second),
					},
				},
			},
			"get-forecast": &oas.MCPPrimitive{},
		},
	}
	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/mcp"
	def.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	ts.Gw.LoadAPI(spec)

	loaded := ts.Gw.getApiSpec(def.APIID)
	require.NotNil(t, loaded)
	assert.True(t, loaded.IsMCP())
	assert.Equal(t, apidef.JsonRPC20, loaded.JsonRpcVersion)
	require.NotEmpty(t, loaded.MCPPrimitives)

	mw := loaded.OAS.GetTykMiddleware()
	require.NotNil(t, mw)
	require.Len(t, mw.McpTools, 2)

	req := httptest.NewRequest(http.MethodPost, "/mcp-tool:get-weather", nil)
	httpctx.SetJsonRPCRouting(req, true) // Simulate JSON-RPC routing context
	var rxPaths []URLSpec
	for _, paths := range loaded.RxPaths {
		rxPaths = paths
		break
	}
	require.NotNil(t, rxPaths)
	_, ok := loaded.FindSpecMatchesStatus(req, rxPaths, RateLimit)
	require.True(t, ok)

	rl := &RateLimitForAPI{BaseMiddleware: &BaseMiddleware{Spec: loaded, Gw: ts.Gw}}
	assert.True(t, rl.EnabledForSpec())

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "get-weather", "arguments": map[string]string{"city": "London"}},
		"id":      1,
	}
	otherPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "get-forecast", "arguments": map[string]string{"city": "London"}},
		"id":      2,
	}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/mcp", Data: payload, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/mcp", Data: payload, Code: http.StatusTooManyRequests},
		{Method: http.MethodPost, Path: "/mcp", Data: otherPayload, Code: http.StatusOK},
	}...)
}

// TestJSONRPCMiddleware_OperationRateLimitNotEnforced_ExactUserScenario demonstrates
// the exact bug reported where operation-level rate limits defined in middleware.operations
// are not enforced when MCP JSON-RPC routing occurs.
// This test matches the user's exact API configuration and should FAIL until the bug is fixed.
//
// Bug: When an API has:
// 1. An OpenAPI operation (/tools/call GET with operationId "testget")
// 2. MCP tool (weather.getForecast) with rate limit: 1 req/20s
// 3. Operation middleware (testget) with rate limit: 1 req/20s
//
// The tool-level rate limit (mcpTools.weather.getForecast.rateLimit) IS enforced.
// The operation-level rate limit (operations.testget.rateLimit) is NOT enforced (BUG!).
func TestJSONRPCMiddleware_OperationRateLimitNotEnforced_ExactUserScenario(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS API matching the user's exact configuration
	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "mcp andrei",
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		},
	}

	// Add the /tools/call GET operation with operationId "testget"
	desc := ""
	oasAPI.Paths.Set("/tools/call", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "testget",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: &desc,
					},
				}),
			),
		},
	})

	// Configure x-tyk-api-gateway extension
	tykExt := &oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "mcp andrei",
			ID:   randStringBytes(8),
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/prct",
				Strip: true,
			},
		},
		Middleware: &oas.Middleware{
			Global: &oas.Global{
				ContextVariables: &oas.ContextVariables{
					Enabled: true,
				},
				TrafficLogs: &oas.TrafficLogs{
					Enabled: true,
				},
			},
			// MCP tool with rate limit 1 req/20s (THIS WORKS)
			McpTools: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
						RateLimit: &oas.RateLimitEndpoint{
							Enabled: true,
							Rate:    1,
							Per:     oas.ReadableDuration(20 * time.Second),
						},
					},
				},
			},
			// Operation-level rate limit 1 req/20s (THIS DOESN'T WORK - BUG!)
			Operations: oas.Operations{
				"testget": &oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    1,
						Per:     oas.ReadableDuration(20 * time.Second),
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
	def.Proxy.ListenPath = "/prct"
	def.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	loadedSpecs := ts.Gw.LoadAPI(spec)
	require.Len(t, loadedSpecs, 1, "Should load 1 API")

	loaded := loadedSpecs[0]
	require.NotNil(t, loaded, "API should be loaded")
	assert.True(t, loaded.IsMCP())

	// JSON-RPC request to call weather.getForecast tool
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "weather.getForecast", "arguments": map[string]string{"location": "London"}},
		"id":      1,
	}

	// First request should succeed (within all rate limits)
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/prct",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Second request should be blocked by BOTH:
	// 1. Tool-level rate limit (mcpTools.weather.getForecast.rateLimit: 1 req/20s) - THIS WORKS
	// 2. Operation-level rate limit (operations.testget.rateLimit: 1 req/20s) - THIS DOESN'T WORK (BUG!)
	//
	// Currently, only the tool-level rate limit is enforced.
	// The operation-level rate limit is ignored, which is the bug.
	//
	// BUG: This test will FAIL because it expects 429 but gets 429 for the wrong reason.
	// The 429 is coming from the tool-level rate limit, not the operation-level rate limit.
	// To properly test this bug, we would need to increase the tool-level rate limit
	// to 100 req/min and keep the operation-level at 1 req/20s, then verify the second
	// request returns 200 instead of 429 (demonstrating the operation limit isn't applied).
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/prct",
		Data:   payload,
		Code:   http.StatusTooManyRequests, // This will pass, but for the wrong reason
	})

	// To truly demonstrate the bug, let's test with a different tool that has generous limits
	oasAPI2 := getSampleOASAPI()
	tykExt2 := oasAPI2.GetTykExtension()
	tykExt2.Info.State.Active = true
	tykExt2.Server.ListenPath = oas.ListenPath{
		Value: "/prct2",
		Strip: true,
	}

	// Add the /tools/call GET operation
	desc2 := ""
	oasAPI2.Paths.Set("/tools/call", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "testget2",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: &desc2,
					},
				}),
			),
		},
	})

	tykExt2.Middleware = &oas.Middleware{
		// MCP tool with GENEROUS rate limit (100 req/min) - should NOT block
		McpTools: oas.MCPPrimitives{
			"weather.getForecast": &oas.MCPPrimitive{
				Operation: oas.Operation{
					RateLimit: &oas.RateLimitEndpoint{
						Enabled: true,
						Rate:    100,
						Per:     oas.ReadableDuration(time.Minute),
					},
				},
			},
		},
		// Operation-level STRICT rate limit (1 req/20s) - SHOULD block but DOESN'T (BUG!)
		Operations: oas.Operations{
			"testget2": &oas.Operation{
				RateLimit: &oas.RateLimitEndpoint{
					Enabled: true,
					Rate:    1,
					Per:     oas.ReadableDuration(20 * time.Second),
				},
			},
		},
	}

	oasAPI2.SetTykExtension(tykExt2)

	var def2 apidef.APIDefinition
	oasAPI2.ExtractTo(&def2)
	def2.IsOAS = true
	def2.UseKeylessAccess = true
	def2.Proxy.ListenPath = "/prct2"
	def2.GlobalRateLimit = apidef.GlobalRateLimit{Rate: 100, Per: 1}
	def2.MarkAsMCP()

	spec2 := &APISpec{APIDefinition: &def2, OAS: oasAPI2}
	loadedSpecs2 := ts.Gw.LoadAPI(spec2)
	require.Len(t, loadedSpecs2, 1, "Should load second API")

	loaded2 := loadedSpecs2[0]
	require.NotNil(t, loaded2, "Second API should be loaded")

	// First request to second API should succeed
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/prct2",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Second request should be blocked by operation-level rate limit (1 req/20s)
	// but tool-level rate limit (100 req/min) allows it
	// BUG: This test will FAIL - expects 429 but gets 200
	// This demonstrates that operation-level rate limits are NOT enforced
	_, _ = ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/prct2",
		Data:   payload,
		Code:   http.StatusTooManyRequests, // Expected: 429, Actual: 200 (BUG!)
	})
}

// TestJSONRPCMiddleware_OperationHeaderInjection tests that headers from both
// operation-level and tool-level middleware are injected in the VEM chain.
func TestJSONRPCMiddleware_OperationHeaderInjection(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS API with /tools/call path
	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "MCP Header Test",
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		},
	}

	// Add /tools/call path with operationId "testget"
	desc := ""
	oasAPI.Paths.Set("/tools/call", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "testget",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: &desc,
					},
				}),
			),
		},
	})

	// Configure x-tyk-api-gateway extension
	tykExt := &oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "MCP Header Test",
			ID:   randStringBytes(8),
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/prct",
				Strip: false,
			},
		},
		Middleware: &oas.Middleware{
			// MCP tool with header injection
			McpTools: oas.MCPPrimitives{
				"weather.getForecast": &oas.MCPPrimitive{
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
						TransformRequestHeaders: &oas.TransformHeaders{
							Enabled: true,
							Add: []oas.Header{
								{Name: "X-Tool-Header", Value: "tool-value"},
							},
						},
						URLRewrite: &oas.URLRewrite{
							Enabled:   true,
							Pattern:   ".*",
							RewriteTo: "/anything",
						},
					},
				},
			},
			// Operation-level header injection
			Operations: oas.Operations{
				"testget": &oas.Operation{
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

	oasAPI.SetTykExtension(tykExt)

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = "/prct"
	def.MarkAsMCP()

	spec := &APISpec{APIDefinition: &def, OAS: oasAPI}
	loadedSpecs := ts.Gw.LoadAPI(spec)
	require.Len(t, loadedSpecs, 1, "Should load 1 API")

	loaded := loadedSpecs[0]
	require.NotNil(t, loaded, "API should be loaded")
	assert.True(t, loaded.IsMCP())

	// Debug: Print all generated rxPaths
	for versionName, rxPaths := range loaded.RxPaths {
		t.Logf("Version %s has %d rxPaths:", versionName, len(rxPaths))
		for i, rxPath := range rxPaths {
			t.Logf("  [%d] Status=%d", i, rxPath.Status)
			if rxPath.Status == HeaderInjected {
				t.Logf("      HeaderInjected: Path=%s, Method=%s, Add=%v",
					rxPath.InjectHeaders.Path, rxPath.InjectHeaders.Method, rxPath.InjectHeaders.AddHeaders)
			}
			if rxPath.Status == Internal {
				t.Logf("      Internal: Path=%s", rxPath.Internal.Path)
			}
		}
	}

	// JSON-RPC request to call weather.getForecast tool
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "weather.getForecast", "arguments": map[string]string{"location": "London"}},
		"id":      1,
	}

	resp, _ := ts.Run(t, test.TestCase{
		Method: http.MethodPost,
		Path:   "/prct",
		Data:   payload,
		Code:   http.StatusOK,
	})

	// Parse response body to check headers
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Should read response body")
	resp.Body.Close()

	t.Logf("Response body: %s", string(bodyBytes))

	var respBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &respBody)
	require.NoError(t, err, "Response should be valid JSON")

	// Check that both headers are present in the upstream request
	headers, ok := respBody["Headers"].(map[string]interface{})
	require.True(t, ok, "Response should have Headers field")

	// Check for tool-level header
	assert.Contains(t, headers, "X-Tool-Header", "Should have tool-level header")
	if toolHeader, ok := headers["X-Tool-Header"].(string); ok {
		assert.Equal(t, "tool-value", toolHeader)
	}

	// Check for operation-level header
	// BUG: This will fail if operation-level headers are not being injected
	assert.Contains(t, headers, "X-Operation-Header", "Should have operation-level header")
	if opHeader, ok := headers["X-Operation-Header"].(string); ok {
		assert.Equal(t, "operation-value", opHeader)
	}
}

func TestJSONRPCMiddleware_setupSequentialRouting(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		expectedNextVEM    string
		expectedVEMChain   []string
		expectedRedirectTo string
	}{
		{
			name:               "tools/call - 2-stage routing",
			method:             "tools/call",
			expectedNextVEM:    "/mcp-tool:weather.getForecast",
			expectedVEMChain:   []string{"/json-rpc-method:tools/call", "/mcp-tool:weather.getForecast"},
			expectedRedirectTo: "/json-rpc-method:tools/call",
		},
		{
			name:               "resources/read - 2-stage routing",
			method:             "resources/read",
			expectedNextVEM:    "/mcp-resource:file:///data/config.json",
			expectedVEMChain:   []string{"/json-rpc-method:resources/read", "/mcp-resource:file:///data/config.json"},
			expectedRedirectTo: "/json-rpc-method:resources/read",
		},
		{
			name:               "prompts/get - 2-stage routing",
			method:             "prompts/get",
			expectedNextVEM:    "/mcp-prompt:summarize",
			expectedVEMChain:   []string{"/json-rpc-method:prompts/get", "/mcp-prompt:summarize"},
			expectedRedirectTo: "/json-rpc-method:prompts/get",
		},
		{
			name:               "tools/list - 1-stage routing (operation only)",
			method:             "tools/list",
			expectedNextVEM:    "",
			expectedVEMChain:   []string{"/json-rpc-method:tools/list"},
			expectedRedirectTo: "/json-rpc-method:tools/list",
		},
		{
			name:               "ping - 1-stage routing (operation only)",
			method:             "ping",
			expectedNextVEM:    "",
			expectedVEMChain:   []string{"/json-rpc-method:ping"},
			expectedRedirectTo: "/json-rpc-method:ping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &JSONRPCMiddleware{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{
						APIDefinition: &apidef.APIDefinition{
							ApplicationProtocol: apidef.AppProtocolMCP,
							JsonRpcVersion:      apidef.JsonRPC20,
						},
					},
				},
			}

			r := httptest.NewRequest("POST", "/prct", nil)
			rpcReq := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  tt.method,
				ID:      123,
			}

			// Call setupSequentialRouting
			mw.setupSequentialRouting(r, rpcReq, tt.expectedVEMChain)

			// Check routing state
			state := httpctx.GetJSONRPCRoutingState(r)
			require.NotNil(t, state, "Routing state should be set")
			assert.Equal(t, tt.method, state.Method, "Method should match")
			assert.Equal(t, tt.expectedNextVEM, state.NextVEM, "NextVEM should match")
			assert.Equal(t, tt.expectedVEMChain, state.VEMChain, "VEMChain should match")
			assert.Equal(t, "/prct", state.OriginalPath, "OriginalPath should match")

			// Check redirect URL (should always point to operation VEM)
			redirectURL := ctxGetURLRewriteTarget(r)
			require.NotNil(t, redirectURL, "Redirect URL should be set")
			assert.Equal(t, "tyk", redirectURL.Scheme, "Scheme should be tyk")
			assert.Equal(t, "self", redirectURL.Host, "Host should be self")
			assert.Equal(t, tt.expectedRedirectTo, redirectURL.Path, "Should redirect to operation VEM")

			// Check JSON-RPC routing flag
			assert.True(t, httpctx.IsJsonRPCRouting(r), "JsonRPCRouting flag should be set")
		})
	}
}
