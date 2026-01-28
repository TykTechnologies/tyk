package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
)

func TestMCPJSONRPCMiddleware_EnabledForSpec(t *testing.T) {
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
			m := &MCPJSONRPCMiddleware{
				BaseMiddleware: &BaseMiddleware{Spec: tt.spec},
			}
			assert.Equal(t, tt.expected, m.EnabledForSpec())
		})
	}
}

func TestMCPJSONRPCMiddleware_ProcessRequest_NonPostPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_NonJSONPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("plain text")))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_InvalidJSON(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil)

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, mcp.JSONRPCParseError, resp.Error.Code)
	assert.Equal(t, "Parse error", resp.Error.Message)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_InvalidRequest(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
	}

	m := &MCPJSONRPCMiddleware{
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
			body, _ := json.Marshal(tt.payload)
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			_, _ = m.ProcessRequest(w, r, nil)

			var resp JSONRPCErrorResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)
			assert.Equal(t, mcp.JSONRPCInvalidRequest, resp.Error.Code)
		})
	}
}

func TestMCPJSONRPCMiddleware_ProcessRequest_ToolsCall_RoutesToVEM(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:get-weather": "/mcp-tool:get-weather",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "get-weather", "arguments": map[string]string{"city": "London"}},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-tool:get-weather", r.URL.Path)
	assert.True(t, httpctx.IsMCPRouting(r))

	rpcData := httpctx.GetJSONRPCRequest(r)
	require.NotNil(t, rpcData)
	assert.Equal(t, "tools/call", rpcData.Method)
	assert.Equal(t, "get-weather", rpcData.Primitive)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_ToolsCall_NotFound(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "unknown-tool"},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil)

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCMethodNotFound, resp.Error.Code)
	assert.Equal(t, 1.0, resp.ID) // JSON numbers decode as float64
}

func TestMCPJSONRPCMiddleware_ProcessRequest_ResourcesRead_ExactMatch(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///config.json": "/mcp-resource:file:///config.json",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///config.json"},
		"id":      "req-1",
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-resource:file:///config.json", r.URL.Path)

	rpcData := httpctx.GetJSONRPCRequest(r)
	require.NotNil(t, rpcData)
	assert.Equal(t, "file:///config.json", rpcData.Primitive)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_ResourcesRead_WildcardMatch(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:file:///repo/*": "/mcp-resource:file:///repo/*",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/read",
		"params":  map[string]interface{}{"uri": "file:///repo/README.md"},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-resource:file:///repo/*", r.URL.Path)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_PromptsGet(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"prompt:code-review": "/mcp-prompt:code-review",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "prompts/get",
		"params":  map[string]interface{}{"name": "code-review"},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-prompt:code-review", r.URL.Path)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_OperationVEM(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"operation:tools/list": "/mcp-operation:tools-list",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-operation:tools-list", r.URL.Path)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_DiscoveryPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{}, // No configured VEMs
	}

	m := &MCPJSONRPCMiddleware{
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
			body, _ := json.Marshal(payload)

			r := httptest.NewRequest(http.MethodPost, "/original-path", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			err, code := m.ProcessRequest(w, r, nil)
			assert.Nil(t, err)
			assert.Equal(t, http.StatusOK, code)
			// Path should not be rewritten for passthrough
			assert.Equal(t, "/original-path", r.URL.Path)
			assert.False(t, httpctx.IsMCPRouting(r))
		})
	}
}

func TestMCPJSONRPCMiddleware_ProcessRequest_NotificationsPassthrough(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/progress",
		// No ID - notifications don't have IDs
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_BodyRestored(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:test": "/mcp-tool:test",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	originalPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": "test", "arguments": map[string]string{"key": "value"}},
		"id":      1,
	}
	originalBody, _ := json.Marshal(originalPayload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(originalBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil)

	// Body should be restored for upstream
	restoredBody, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, restoredBody)
}

func TestMCPJSONRPCMiddleware_ProcessRequest_NullID(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// JSON with null ID
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"unknown"},"id":null}`)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil)

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCMethodNotFound, resp.Error.Code)
	assert.Nil(t, resp.ID) // ID should be preserved as null
}

func TestMCPJSONRPCMiddleware_MatchesWildcard(t *testing.T) {
	m := &MCPJSONRPCMiddleware{}

	tests := []struct {
		pattern  string
		uri      string
		expected bool
	}{
		{"file:///repo/*", "file:///repo/README.md", true},
		{"file:///repo/*", "file:///repo/src/main.go", true},
		{"file:///repo/*", "file:///other/file.txt", false},
		{"file:///exact.txt", "file:///exact.txt", true},
		{"file:///exact.txt", "file:///other.txt", false},
		{"http://api/*", "http://api/users/123", true},
		{"http://api/*", "http://api/", true},
		{"http://api/*", "http://other/", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.uri, func(t *testing.T) {
			result := m.matchesWildcard(tt.pattern, tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMCPJSONRPCMiddleware_ExtractParamString(t *testing.T) {
	m := &MCPJSONRPCMiddleware{}

	tests := []struct {
		name     string
		params   json.RawMessage
		key      string
		expected string
	}{
		{
			name:     "extract name",
			params:   json.RawMessage(`{"name":"test-tool","arguments":{}}`),
			key:      "name",
			expected: "test-tool",
		},
		{
			name:     "extract uri",
			params:   json.RawMessage(`{"uri":"file:///test.txt"}`),
			key:      "uri",
			expected: "file:///test.txt",
		},
		{
			name:     "missing key",
			params:   json.RawMessage(`{"other":"value"}`),
			key:      "name",
			expected: "",
		},
		{
			name:     "empty params",
			params:   json.RawMessage(``),
			key:      "name",
			expected: "",
		},
		{
			name:     "invalid json",
			params:   json.RawMessage(`not json`),
			key:      "name",
			expected: "",
		},
		{
			name:     "non-string value",
			params:   json.RawMessage(`{"name":123}`),
			key:      "name",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.extractParamString(tt.params, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMCPJSONRPCMiddleware_MapJSONRPCErrorToHTTP(t *testing.T) {
	m := &MCPJSONRPCMiddleware{}

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

func TestMCPJSONRPCMiddleware_ResourcesSubscribe(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:events://*": "/mcp-resource:events://*",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/subscribe",
		"params":  map[string]interface{}{"uri": "events://updates"},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-resource:events://*", r.URL.Path)
}

func TestMCPJSONRPCMiddleware_ResourcesUnsubscribe(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"resource:events://topic": "/mcp-resource:events://topic",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/unsubscribe",
		"params":  map[string]interface{}{"uri": "events://topic"},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, r, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "/mcp-resource:events://topic", r.URL.Path)
}

func TestMCPJSONRPCMiddleware_ToolsCall_MissingParamsName(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			JsonRpcVersion:      apidef.JsonRPC20,
		},
		MCPPrimitives: map[string]string{
			"tool:test": "/mcp-tool:test",
		},
	}

	m := &MCPJSONRPCMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// Missing params.name
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  map[string]interface{}{"arguments": map[string]string{}},
		"id":      1,
	}
	body, _ := json.Marshal(payload)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	_, _ = m.ProcessRequest(w, r, nil)

	var resp JSONRPCErrorResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, mcp.JSONRPCMethodNotFound, resp.Error.Code)
}
