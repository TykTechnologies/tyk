package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// defaultJSONRPCRequestSize is the default maximum size for JSON-RPC request bodies (1MB).
// Used when no gateway-level MaxRequestBodySize is configured.
const defaultJSONRPCRequestSize int64 = 1 << 20

// MCPJSONRPCMiddleware handles JSON-RPC 2.0 request detection and routing for MCP APIs.
// When a client sends a JSON-RPC request to an MCP endpoint, the middleware detects it,
// extracts the method and primitive name, routes to the correct VEM, and enables
// the middleware chain to execute before proxying to upstream.
type MCPJSONRPCMiddleware struct {
	*BaseMiddleware
}

// JSONRPCRequest represents a JSON-RPC 2.0 request structure.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSONRPCErrorResponse represents a JSON-RPC 2.0 error response.
type JSONRPCErrorResponse struct {
	JSONRPC string       `json:"jsonrpc"`
	Error   JSONRPCError `json:"error"`
	ID      interface{}  `json:"id"`
}

// Name returns the middleware name.
func (m *MCPJSONRPCMiddleware) Name() string {
	return "MCPJSONRPCMiddleware"
}

// EnabledForSpec returns true if this middleware should be enabled for the API spec.
// It requires the API to be an MCP API with JSON-RPC 2.0 protocol.
func (m *MCPJSONRPCMiddleware) EnabledForSpec() bool {
	return m.Spec.IsMCP() && m.Spec.JsonRpcVersion == apidef.JsonRPC20
}

// getMaxRequestBodySize returns the maximum allowed request body size.
// It uses the gateway-level MaxRequestBodySize if configured, otherwise falls back to the default.
func (m *MCPJSONRPCMiddleware) getMaxRequestBodySize() int64 {
	if m.Gw != nil {
		if maxSize := m.Gw.GetConfig().HttpServerOptions.MaxRequestBodySize; maxSize > 0 {
			return maxSize
		}
	}
	return defaultJSONRPCRequestSize
}

// ProcessRequest handles JSON-RPC request detection and routing.
//
//nolint:staticcheck // ST1008: middleware interface requires (error, int) return order
func (m *MCPJSONRPCMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Only process POST requests with JSON content type
	if r.Method != http.MethodPost {
		return nil, http.StatusOK
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, http.StatusOK
	}

	// Read and parse the request body with size limit to prevent DoS
	body, err := io.ReadAll(io.LimitReader(r.Body, m.getMaxRequestBodySize()))
	if err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, "Parse error", nil)
		return nil, middleware.StatusRespond //nolint:nilerr // error handled via JSON-RPC response
	}
	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, "Parse error", nil)
		return nil, middleware.StatusRespond //nolint:nilerr // error handled via JSON-RPC response
	}

	// Validate JSON-RPC 2.0 structure
	if rpcReq.JSONRPC != apidef.JsonRPC20 || rpcReq.Method == "" {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidRequest, "Invalid Request", nil)
		return nil, middleware.StatusRespond
	}

	// Route based on method
	vemPath, primitive, found, invalidParams := m.routeRequest(&rpcReq)
	if invalidParams {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidParams, "Invalid params", nil)
		return nil, middleware.StatusRespond
	}
	if !found || vemPath == "" {
		// Unregistered primitives or operations (notifications, discovery, etc.)
		// passthrough to upstream unchanged. The upstream MCP server will handle them.
		return nil, http.StatusOK
	}

	// Store parsed data in context
	httpctx.SetJSONRPCRequest(r, &httpctx.JSONRPCRequestData{
		Method:    rpcReq.Method,
		Params:    rpcReq.Params,
		ID:        rpcReq.ID,
		VEMPath:   vemPath,
		Primitive: primitive,
	})

	// Enable JSON-RPC routing (allows access to internal VEM endpoints)
	httpctx.SetJsonRPCRouting(r, true)

	// Set loop level to enable internal routing
	ctxSetLoopLevel(r, 1)
	// Ensure limits and quotas apply to MCP routed requests
	ctxSetCheckLoopLimits(r, true)

	// Rewrite URL path to VEM path
	r.URL.Path = vemPath

	return nil, http.StatusOK
}

// buildUnregisteredVEMPath constructs a VEM path for an unregistered primitive.
// This path will be caught by the catch-all BlackList VEM when allow list is enabled.
func (m *MCPJSONRPCMiddleware) buildUnregisteredVEMPath(rpcReq *JSONRPCRequest, primitive string) string {
	switch rpcReq.Method {
	case mcp.MethodToolsCall:
		return mcp.ToolPrefix + primitive
	case mcp.MethodResourcesRead:
		return mcp.ResourcePrefix + primitive
	case mcp.MethodPromptsGet:
		return mcp.PromptPrefix + primitive
	default:
		return ""
	}
}

// routeRequest determines the VEM path for a JSON-RPC request based on its method.
// Returns the VEM path, primitive name, match status, and invalid params flag.
func (m *MCPJSONRPCMiddleware) routeRequest(rpcReq *JSONRPCRequest) (vemPath string, primitive string, found bool, invalidParams bool) {
	primitives := m.Spec.MCPPrimitives

	switch rpcReq.Method {
	case mcp.MethodToolsCall:
		// Extract tool name from params.name
		name := m.extractParamString(rpcReq.Params, "name")
		if name == "" {
			return "", "", false, true
		}
		vemPath, found = primitives["tool:"+name]
		primitive = name

	case mcp.MethodResourcesRead:
		// Extract resource URI from params.uri
		uri := m.extractParamString(rpcReq.Params, "uri")
		if uri == "" {
			return "", "", false, true
		}
		vemPath, found = m.matchResourceURI(uri, primitives)
		primitive = uri

	case mcp.MethodPromptsGet:
		// Extract prompt name from params.name
		name := m.extractParamString(rpcReq.Params, "name")
		if name == "" {
			return "", "", false, true
		}
		vemPath, found = primitives["prompt:"+name]
		primitive = name

	default:
		// Check for operation-level VEMs (tools/list, initialize, etc.)
		vemPath, found = primitives["operation:"+rpcReq.Method]
		primitive = rpcReq.Method
	}

	// When allowlist is enabled and primitive not found, route to catch-all VEM
	if !found && m.Spec.MCPAllowListEnabled {
		vemPath = m.buildUnregisteredVEMPath(rpcReq, primitive)
		found = true
	}

	return vemPath, primitive, found, false
}

// extractParamString extracts a string parameter from JSON-RPC params.
func (m *MCPJSONRPCMiddleware) extractParamString(params json.RawMessage, key string) string {
	if len(params) == 0 {
		return ""
	}

	var paramsMap map[string]interface{}
	if err := json.Unmarshal(params, &paramsMap); err != nil {
		return ""
	}

	if val, ok := paramsMap[key].(string); ok {
		return val
	}
	return ""
}

// matchResourceURI matches a resource URI against configured patterns.
// It first tries an exact match, then falls back to wildcard matching.
func (m *MCPJSONRPCMiddleware) matchResourceURI(uri string, primitives map[string]string) (vemPath string, found bool) {
	// Exact match first
	if path, ok := primitives["resource:"+uri]; ok {
		return path, true
	}

	// Wildcard matching with deterministic precedence.
	var bestPattern string
	var bestPath string
	bestPrefixLen := -1

	for key, path := range primitives {
		if !strings.HasPrefix(key, "resource:") {
			continue
		}
		pattern := strings.TrimPrefix(key, "resource:")
		if m.matchesWildcard(pattern, uri) {
			prefixLen := len(pattern)
			if strings.HasSuffix(pattern, "/*") {
				prefixLen = len(strings.TrimSuffix(pattern, "*"))
			}

			if prefixLen > bestPrefixLen || (prefixLen == bestPrefixLen && pattern < bestPattern) {
				bestPattern = pattern
				bestPath = path
				bestPrefixLen = prefixLen
			}
		}
	}

	if bestPrefixLen >= 0 {
		return bestPath, true
	}

	return "", false
}

// matchesWildcard checks if a URI matches a wildcard pattern.
// Supports suffix wildcards: "file:///repo/*" matches "file:///repo/README.md"
func (m *MCPJSONRPCMiddleware) matchesWildcard(pattern, uri string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(uri, prefix)
	}
	return pattern == uri
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response.
func (m *MCPJSONRPCMiddleware) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(response) //nolint:errcheck
}

// mapJSONRPCErrorToHTTP maps JSON-RPC error codes to HTTP status codes.
func (m *MCPJSONRPCMiddleware) mapJSONRPCErrorToHTTP(code int) int {
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
