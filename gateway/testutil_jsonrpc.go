package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// MockJSONRPCServer provides a configurable mock JSON-RPC 2.0 server for testing.
// It supports static mock responses, dynamic handlers for assertions, and request recording.
type MockJSONRPCServer struct {
	Server *httptest.Server

	// mu protects all maps below
	mu sync.RWMutex

	// mockedMethods maps method names to static JSON-RPC responses
	mockedMethods map[string]json.RawMessage

	// handlers maps method names to dynamic handlers that can assert on requests
	handlers map[string]JSONRPCHandler

	// receivedRequests records all received requests for later assertions
	receivedRequests []ReceivedJSONRPCRequest

	// defaultResponse is returned for unmocked methods (if set)
	defaultResponse json.RawMessage

	// errorOnUnmocked returns method_not_found error for unmocked methods (default: true)
	errorOnUnmocked bool
}

// JSONRPCHandler is a function that handles a JSON-RPC request and returns a result or error.
type JSONRPCHandler func(t *testing.T, method string, params json.RawMessage) (result any, errCode int, errMsg string)

// ReceivedJSONRPCRequest records a received JSON-RPC request for later assertions.
type ReceivedJSONRPCRequest struct {
	Method  string
	Params  json.RawMessage
	ID      any
	Headers http.Header // HTTP headers received with the request
}

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  any              `json:"result,omitempty"`
	Error   *jsonRPCError    `json:"error,omitempty"`
	ID      any              `json:"id"`
}

// jsonRPCError represents a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// NewMockJSONRPCServer creates a new mock JSON-RPC server.
func NewMockJSONRPCServer() *MockJSONRPCServer {
	m := &MockJSONRPCServer{
		mockedMethods:   make(map[string]json.RawMessage),
		handlers:        make(map[string]JSONRPCHandler),
		errorOnUnmocked: true,
	}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handleRequest))
	return m
}

// URL returns the URL of the mock server.
func (m *MockJSONRPCServer) URL() string {
	return m.Server.URL
}

// Close shuts down the mock server.
func (m *MockJSONRPCServer) Close() {
	m.Server.Close()
}

// Reset clears all mocked methods, handlers, and recorded requests.
func (m *MockJSONRPCServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockedMethods = make(map[string]json.RawMessage)
	m.handlers = make(map[string]JSONRPCHandler)
	m.receivedRequests = nil
	m.defaultResponse = nil
}

// MockMethod sets a static response for a JSON-RPC method.
// The result will be returned in the "result" field of the JSON-RPC response.
func (m *MockJSONRPCServer) MockMethod(method string, result any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, _ := json.Marshal(result)
	m.mockedMethods[method] = data
}

// MockMethodRaw sets a raw JSON response for a JSON-RPC method.
func (m *MockJSONRPCServer) MockMethodRaw(method string, rawResult json.RawMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mockedMethods[method] = rawResult
}

// MockMethodHandler sets a dynamic handler for a JSON-RPC method.
// The handler can perform assertions and return dynamic results.
func (m *MockJSONRPCServer) MockMethodHandler(method string, handler JSONRPCHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[method] = handler
}

// SetDefaultResponse sets a default response for unmocked methods.
// If set, errorOnUnmocked is automatically set to false.
func (m *MockJSONRPCServer) SetDefaultResponse(result any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, _ := json.Marshal(result)
	m.defaultResponse = data
	m.errorOnUnmocked = false
}

// SetErrorOnUnmocked controls whether unmocked methods return an error (default: true).
func (m *MockJSONRPCServer) SetErrorOnUnmocked(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOnUnmocked = enabled
}

// ReceivedRequests returns all received JSON-RPC requests.
func (m *MockJSONRPCServer) ReceivedRequests() []ReceivedJSONRPCRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ReceivedJSONRPCRequest, len(m.receivedRequests))
	copy(result, m.receivedRequests)
	return result
}

// ReceivedRequestsForMethod returns all received requests for a specific method.
func (m *MockJSONRPCServer) ReceivedRequestsForMethod(method string) []ReceivedJSONRPCRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []ReceivedJSONRPCRequest
	for _, req := range m.receivedRequests {
		if req.Method == method {
			result = append(result, req)
		}
	}
	return result
}

// handleRequest handles incoming HTTP requests to the mock server.
func (m *MockJSONRPCServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		m.writeError(w, nil, -32700, "Parse error", nil)
		return
	}

	// Record the request with headers
	m.mu.Lock()
	m.receivedRequests = append(m.receivedRequests, ReceivedJSONRPCRequest{
		Method:  req.Method,
		Params:  req.Params,
		ID:      req.ID,
		Headers: r.Header.Clone(),
	})
	m.mu.Unlock()

	// Check for dynamic handler first
	m.mu.RLock()
	handler, hasHandler := m.handlers[req.Method]
	m.mu.RUnlock()

	if hasHandler {
		// Call handler - note: we pass nil for t since we don't have access to it here
		// In practice, users should use MockMethodHandler with a closure that captures t
		result, errCode, errMsg := handler(nil, req.Method, req.Params)
		if errCode != 0 {
			m.writeError(w, req.ID, errCode, errMsg, nil)
			return
		}
		m.writeResult(w, req.ID, result)
		return
	}

	// Check for static mock
	m.mu.RLock()
	mockResult, hasMock := m.mockedMethods[req.Method]
	defaultResp := m.defaultResponse
	errorOnUnmocked := m.errorOnUnmocked
	m.mu.RUnlock()

	if hasMock {
		m.writeRawResult(w, req.ID, mockResult)
		return
	}

	// Use default response if available
	if defaultResp != nil {
		m.writeRawResult(w, req.ID, defaultResp)
		return
	}

	// Return error for unmocked method
	if errorOnUnmocked {
		m.writeError(w, req.ID, -32601, "Method not found", nil)
		return
	}

	// Return empty result
	m.writeResult(w, req.ID, nil)
}

// writeResult writes a successful JSON-RPC response.
func (m *MockJSONRPCServer) writeResult(w http.ResponseWriter, id any, result any) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeRawResult writes a successful JSON-RPC response with a raw JSON result.
func (m *MockJSONRPCServer) writeRawResult(w http.ResponseWriter, id any, rawResult json.RawMessage) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
	}

	// Unmarshal raw result to interface{} to properly embed in response
	var result any
	if len(rawResult) > 0 {
		json.Unmarshal(rawResult, &result)
	}
	resp.Result = result

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeError writes a JSON-RPC error response.
func (m *MockJSONRPCServer) writeError(w http.ResponseWriter, id any, code int, message string, data any) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// JSONRPCTestCase extends test.TestCase with JSON-RPC specific fields.
type JSONRPCTestCase struct {
	Method    string // JSON-RPC method to call
	Params    any    // Parameters for the method
	ID        any    // Request ID (default: 1)
	ExpectErr bool   // Whether to expect a JSON-RPC error
	ErrCode   int    // Expected error code (if ExpectErr is true)
}

// BuildJSONRPCRequest builds a JSON-RPC 2.0 request payload.
func BuildJSONRPCRequest(method string, params any, id any) map[string]any {
	if id == nil {
		id = 1
	}
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"id":      id,
	}
	if params != nil {
		req["params"] = params
	}
	return req
}

// BuildToolsCallRequest builds a JSON-RPC request for tools/call.
func BuildToolsCallRequest(toolName string, arguments map[string]any, id any) map[string]any {
	params := map[string]any{
		"name": toolName,
	}
	if arguments != nil {
		params["arguments"] = arguments
	}
	return BuildJSONRPCRequest("tools/call", params, id)
}

// BuildResourcesReadRequest builds a JSON-RPC request for resources/read.
func BuildResourcesReadRequest(uri string, id any) map[string]any {
	return BuildJSONRPCRequest("resources/read", map[string]any{"uri": uri}, id)
}

// BuildPromptsGetRequest builds a JSON-RPC request for prompts/get.
func BuildPromptsGetRequest(name string, arguments map[string]any, id any) map[string]any {
	params := map[string]any{
		"name": name,
	}
	if arguments != nil {
		params["arguments"] = arguments
	}
	return BuildJSONRPCRequest("prompts/get", params, id)
}

// ParseJSONRPCResponse parses a JSON-RPC response from a byte slice.
func ParseJSONRPCResponse(data []byte) (*jsonRPCResponse, error) {
	var resp jsonRPCResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
