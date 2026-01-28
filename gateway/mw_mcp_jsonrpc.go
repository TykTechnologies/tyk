package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

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

// ProcessRequest handles JSON-RPC request detection and routing.
func (m *MCPJSONRPCMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Only process POST requests with JSON content type
	if r.Method != http.MethodPost {
		return nil, http.StatusOK
	}

	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return nil, http.StatusOK
	}

	// Read and parse the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, "Parse error", nil)
		return nil, middleware.StatusRespond
	}
	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, "Parse error", nil)
		return nil, middleware.StatusRespond
	}

	// Validate JSON-RPC 2.0 structure
	if rpcReq.JSONRPC != "2.0" || rpcReq.Method == "" {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidRequest, "Invalid Request", nil)
		return nil, middleware.StatusRespond
	}

	// Notifications are observational and should pass through unchanged.
	if m.shouldPassthrough(rpcReq.Method) {
		return nil, http.StatusOK
	}

	// Route based on method
	vemPath, primitive, found, invalidParams := m.routeRequest(&rpcReq)
	if invalidParams {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidParams, "Invalid params", nil)
		return nil, middleware.StatusRespond
	}
	if !found {
		if m.mcpAllowListEnabled() {
			m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCMethodNotFound, "Method not found", nil)
			return nil, middleware.StatusRespond
		}
		// Passthrough for unmatched primitives/operations.
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

	// Enable MCP routing (allows access to internal VEM endpoints)
	httpctx.SetMCPRouting(r, true)

	// Set loop level to enable internal routing
	ctxSetLoopLevel(r, 1)
	// Ensure limits and quotas apply to MCP routed requests
	ctxSetCheckLoopLimits(r, true)

	// Rewrite URL path to VEM path
	r.URL.Path = vemPath

	return nil, http.StatusOK
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
		return vemPath, name, found, false

	case mcp.MethodResourcesRead, mcp.MethodResourcesSubscribe, mcp.MethodResourcesUnsubscribe:
		// Extract resource URI from params.uri
		uri := m.extractParamString(rpcReq.Params, "uri")
		if uri == "" {
			return "", "", false, true
		}
		vemPath, found = m.matchResourceURI(uri, primitives)
		return vemPath, uri, found, false

	case mcp.MethodPromptsGet:
		// Extract prompt name from params.name
		name := m.extractParamString(rpcReq.Params, "name")
		if name == "" {
			return "", "", false, true
		}
		vemPath, found = primitives["prompt:"+name]
		return vemPath, name, found, false

	default:
		// Check for operation-level VEMs (tools/list, initialize, etc.)
		vemPath, found = primitives["operation:"+rpcReq.Method]
		return vemPath, rpcReq.Method, found, false
	}
}

func (m *MCPJSONRPCMiddleware) mcpAllowListEnabled() bool {
	mw := m.Spec.OAS.GetTykMiddleware()
	if mw == nil {
		return false
	}

	return m.mcpAllowListEnabledForPrimitives(mw.McpTools) ||
		m.mcpAllowListEnabledForPrimitives(mw.McpResources) ||
		m.mcpAllowListEnabledForPrimitives(mw.McpPrompts)
}

func (m *MCPJSONRPCMiddleware) mcpAllowListEnabledForPrimitives(primitives oas.MCPPrimitives) bool {
	for _, primitive := range primitives {
		if primitive == nil || primitive.Allow == nil || !primitive.Allow.Enabled {
			continue
		}
		return true
	}

	return false
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

// shouldPassthrough returns true if the method should be passed through to upstream
// without requiring a configured VEM (e.g., discovery operations, notifications).
func (m *MCPJSONRPCMiddleware) shouldPassthrough(method string) bool {
	// Notifications are observational and don't require policy enforcement.
	return strings.HasPrefix(method, "notifications/")
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response.
func (m *MCPJSONRPCMiddleware) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string, data interface{}) {
	response := JSONRPCErrorResponse{
		JSONRPC: "2.0",
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
