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
	"github.com/TykTechnologies/tyk/internal/otel"
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
func (m *JSONRPCMiddleware) setupSequentialRouting(r *http.Request, rpcReq *JSONRPCRequest, vemChain []string) {
	if len(vemChain) == 0 {
		return
	}

	method := rpcReq.Method

	var nextVEM string
	if len(vemChain) > 1 {
		nextVEM = vemChain[1]
	}

	state := &httpctx.JSONRPCRoutingState{
		Method:       method,
		Params:       rpcReq.Params,
		ID:           rpcReq.ID,
		NextVEM:      nextVEM,
		OriginalPath: r.URL.Path,
		VEMChain:     vemChain,
		VisitedVEMs:  []string{},
	}

	httpctx.SetJSONRPCRoutingState(r, state)
	httpctx.SetJsonRPCRouting(r, true)
	ctxSetCheckLoopLimits(r, true)

	ctxSetURLRewriteTarget(r, &url.URL{
		Scheme:   "tyk",
		Host:     "self",
		Path:     vemChain[0],
		RawQuery: "check_limits=true",
	})
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

	// Store JSON-RPC request data for access logging
	var vemPath string
	if len(result.VEMChain) > 0 {
		vemPath = result.VEMChain[len(result.VEMChain)-1] // Final destination VEM
	}
	httpctx.SetJSONRPCRequest(r, &httpctx.JSONRPCRequestData{
		Method:    rpcReq.Method,
		Params:    rpcReq.Params,
		ID:        rpcReq.ID,
		VEMPath:   vemPath,
		Primitive: result.PrimitiveName,
		VEMChain:  result.VEMChain,
	})

	// Set MCP span attributes for OpenTelemetry tracing
	m.setMCPSpanAttributes(r, rpcReq, result)

	m.setupSequentialRouting(r, rpcReq, result.VEMChain)

	// Return StatusOK to allow chain to continue to DummyProxyHandler, which will handle the redirect
	return nil, http.StatusOK
}

// setMCPSpanAttributes sets MCP-specific OpenTelemetry span attributes
// according to the OTel MCP Semantic Conventions.
// Reference: https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/
func (m *JSONRPCMiddleware) setMCPSpanAttributes(r *http.Request, rpcReq *JSONRPCRequest, result jsonrpc.RouteResult) {
	attrs := []otel.SpanAttribute{
		// Required: mcp.method.name
		otel.MCPMethodNameAttribute(rpcReq.Method),
		// Recommended: jsonrpc.protocol.version
		otel.JSONRPCProtocolVersionAttribute(apidef.JsonRPC20),
	}

	// Conditionally required: jsonrpc.request.id
	if rpcReq.ID != nil {
		switch id := rpcReq.ID.(type) {
		case string:
			attrs = append(attrs, otel.JSONRPCRequestIDAttribute(id))
		case float64:
			attrs = append(attrs, otel.JSONRPCRequestIDIntAttribute(int64(id)))
		}
	}

	// Method-specific attributes
	switch rpcReq.Method {
	case mcp.MethodToolsCall:
		attrs = append(attrs,
			otel.GenAIToolNameAttribute(result.PrimitiveName),
			otel.GenAIOperationNameAttribute(otel.GenAIOperationExecuteTool),
		)
	case mcp.MethodResourcesRead:
		attrs = append(attrs, otel.MCPResourceURIAttribute(result.PrimitiveName))
	case mcp.MethodPromptsGet:
		attrs = append(attrs, otel.GenAIPromptNameAttribute(result.PrimitiveName))
	}

	ctxSetSpanAttributes(r, m.Name(), attrs...)
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response.
func (m *JSONRPCMiddleware) writeJSONRPCError(w http.ResponseWriter, r *http.Request, id any, code int, message string, data any) {
	// Store error for access logging
	if r != nil {
		httpctx.SetJSONRPCError(r, &httpctx.JSONRPCErrorData{
			Code:    code,
			Message: message,
		})
	}

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
