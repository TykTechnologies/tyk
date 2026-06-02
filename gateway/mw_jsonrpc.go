package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

const (
	contentTypeJSON   = "application/json"
	headerContentType = "Content-Type"
)

// JSONRPCMiddleware handles JSON-RPC 2.0 request detection and routing.
// When a client sends a JSON-RPC request to a JSON-RPC endpoint, the middleware detects it,
// extracts the method, routes to the correct VEM, and enables the middleware chain to execute
// before proxying to upstream.
type JSONRPCMiddleware struct {
	*BaseMiddleware
}

// JSONRPCRequest represents a JSON-RPC 2.0 request structure.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSONRPCErrorResponse represents a JSON-RPC 2.0 error response.
type JSONRPCErrorResponse struct {
	JSONRPC string       `json:"jsonrpc"`
	Error   JSONRPCError `json:"error"`
	ID      any          `json:"id"`
}

// Name returns the middleware name.
func (m *JSONRPCMiddleware) Name() string {
	return "JSONRPCMiddleware"
}

// EnabledForSpec returns true if this middleware should be enabled for the API spec.
// It requires the API to use JSON-RPC 2.0 protocol.
func (m *JSONRPCMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCP() && m.Spec.JsonRpcVersion == apidef.JsonRPC20
}

// validateJSONRPCRequest checks if the request is a valid POST with JSON content type.
// Returns true if valid, false if the request should be passed through.
func (m *JSONRPCMiddleware) validateJSONRPCRequest(r *http.Request) bool {
	// Only process POST requests with JSON content type
	if r.Method != http.MethodPost {
		return false
	}

	contentType := r.Header.Get(headerContentType)
	return strings.HasPrefix(contentType, contentTypeJSON)
}

// readAndParseJSONRPC reads the request body and parses it as JSON-RPC 2.0.
// Returns the parsed request or writes an error response and returns nil.
// Request body size limits are enforced at the gateway level (proxy_muxer).
func (m *JSONRPCMiddleware) readAndParseJSONRPC(w http.ResponseWriter, r *http.Request) (*JSONRPCRequest, error) {
	// Read the request body (already size-limited by gateway if configured)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.writeJSONRPCError(w, r, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, err
	}
	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		m.writeJSONRPCError(w, r, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, err
	}

	// Validate JSON-RPC 2.0 structure
	if rpcReq.JSONRPC != apidef.JsonRPC20 || rpcReq.Method == "" {
		m.writeJSONRPCError(w, r, rpcReq.ID, mcp.JSONRPCInvalidRequest, mcp.ErrMsgInvalidRequest, nil)
		return nil, fmt.Errorf("invalid JSON-RPC request")
	}

	return &rpcReq, nil
}

// setupSequentialRouting initializes sequential VEM routing for JSON-RPC requests.
// The routing strategy (operation → primitive) is determined by the router implementation.
func (m *JSONRPCMiddleware) setupSequentialRouting(r *http.Request, rpcReq *JSONRPCRequest, result jsonrpc.RouteResult) {
	if len(result.VEMChain) == 0 {
		return
	}

	method := rpcReq.Method

	var nextVEM string
	if len(result.VEMChain) > 1 {
		nextVEM = result.VEMChain[1]
	}

	state := &httpctx.JSONRPCRoutingState{
		Method:        method,
		Params:        rpcReq.Params,
		ID:            rpcReq.ID,
		NextVEM:       nextVEM,
		OriginalPath:  r.URL.Path,
		VEMChain:      result.VEMChain,
		VisitedVEMs:   []string{},
		PrimitiveType: primitiveTypeForMethod(method),
		PrimitiveName: result.PrimitiveName,
	}

	httpctx.SetJSONRPCRoutingState(r, state)
	httpctx.SetJsonRPCRouting(r, true)
	ctxSetCheckLoopLimits(r, true)

	ctxSetURLRewriteTarget(r, &url.URL{
		Scheme:   "tyk",
		Host:     "self",
		Path:     result.VEMChain[0],
		RawQuery: "check_limits=true",
	})
}

// primitiveTypeForMethod maps a JSON-RPC method name to its MCP primitive type.
// Returns the primitive type string or "" for non-primitive methods.
func primitiveTypeForMethod(method string) string {
	switch method {
	case mcp.MethodToolsCall:
		return mcp.PrimitiveTypeTool
	case mcp.MethodResourcesRead:
		return mcp.PrimitiveTypeResource
	case mcp.MethodPromptsGet:
		return mcp.PrimitiveTypePrompt
	default:
		return ""
	}
}

// ProcessRequest handles JSON-RPC request detection and routing.
//
//nolint:staticcheck // ST1008: middleware interface requires (error, int) return order
func (m *JSONRPCMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ any) (error, int) {
	// Skip if routing already initialized (we're at a VEM path, not the listen path)
	// This middleware should only run ONCE at the listen path to parse and route the request
	if httpctx.GetJSONRPCRoutingState(r) != nil {
		return nil, http.StatusOK
	}

	// Validate request type
	if !m.validateJSONRPCRequest(r) {
		return nil, http.StatusOK
	}

	// Parse JSON-RPC request
	rpcReq, err := m.readAndParseJSONRPC(w, r)
	if err != nil {
		// Error response already written by readAndParseJSONRPC
		return nil, middleware.StatusRespond //nolint:nilerr
	}

	// Route based on method
	result, err := m.Spec.JSONRPCRouter.RouteMethod(
		rpcReq.Method,
		rpcReq.Params,
		m.Spec.MCPPrimitives,
	)
	if err != nil {
		m.writeJSONRPCError(w, r, rpcReq.ID, mcp.JSONRPCInvalidParams, err.Error(), nil)
		return nil, middleware.StatusRespond
	}

	m.setupSequentialRouting(r, rpcReq, result)

	// Propagate MCP fields to request context for metrics, audit logs, and traces.
	// Set early (before access control) so rejected requests still carry MCP context.
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil {
		ctxSetMCPMethod(r, state.Method)
		ctxSetMCPPrimitiveType(r, state.PrimitiveType)
		ctxSetMCPPrimitiveName(r, state.PrimitiveName)
	}

	// Return StatusOK to allow chain to continue to DummyProxyHandler, which will handle the redirect
	return nil, http.StatusOK
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response.
func (m *JSONRPCMiddleware) writeJSONRPCError(w http.ResponseWriter, r *http.Request, id any, code int, message string, data any) {
	ctxSetJSONRPCErrorCode(r, code)

	response := JSONRPCErrorResponse{
		JSONRPC: apidef.JsonRPC20,
		Error: JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}

	httpCode := m.mapJSONRPCErrorToHTTP(code)

	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(response) //nolint:errcheck
}

// mapJSONRPCErrorToHTTP maps JSON-RPC error codes to HTTP status codes.
func (m *JSONRPCMiddleware) mapJSONRPCErrorToHTTP(code int) int {
	switch {
	case code == mcp.JSONRPCParseError || code == mcp.JSONRPCInvalidRequest:
		return http.StatusBadRequest
	case code == mcp.JSONRPCMethodNotFound:
		return http.StatusNotFound
	case code == mcp.JSONRPCInvalidParams:
		return http.StatusBadRequest
	case code >= -32099 && code <= -32000:
		// Server errors (e.g., policy violations)
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
