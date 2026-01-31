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

// defaultJSONRPCRequestSize is the default maximum size for JSON-RPC request bodies (1MB).
// Used when no gateway-level MaxRequestBodySize is configured.
const defaultJSONRPCRequestSize int64 = 1 << 20

const (
	contentTypeJSON        = "application/json"
	headerContentType      = "Content-Type"
	resourceWildcardSuffix = "/*"
)

// methodPrefixMap maps JSON-RPC methods to their corresponding VEM prefixes
var methodPrefixMap = map[string]string{
	mcp.MethodToolsCall:     mcp.ToolPrefix,
	mcp.MethodResourcesRead: mcp.ResourcePrefix,
	mcp.MethodPromptsGet:    mcp.PromptPrefix,
}

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

// isAllowListEnabled returns true if either MCP primitive or operation allowlist is enabled.
func (m *MCPJSONRPCMiddleware) isAllowListEnabled() bool {
	return m.Spec.MCPAllowListEnabled || m.Spec.OperationsAllowListEnabled
}

// isPrimitiveInvokingMethod returns true if the method invokes an MCP primitive (tool, resource, or prompt).
func isPrimitiveInvokingMethod(method string) bool {
	return method == mcp.MethodToolsCall ||
		method == mcp.MethodResourcesRead ||
		method == mcp.MethodPromptsGet
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

// validateJSONRPCRequest checks if the request is a valid POST with JSON content type.
// Returns true if valid, false if the request should be passed through.
func (m *MCPJSONRPCMiddleware) validateJSONRPCRequest(r *http.Request) bool {
	// Only process POST requests with JSON content type
	if r.Method != http.MethodPost {
		return false
	}

	contentType := r.Header.Get(headerContentType)
	return strings.HasPrefix(contentType, contentTypeJSON)
}

// readAndParseJSONRPC reads the request body and parses it as JSON-RPC 2.0.
// Returns the parsed request or writes an error response and returns nil.
func (m *MCPJSONRPCMiddleware) readAndParseJSONRPC(w http.ResponseWriter, r *http.Request) (*JSONRPCRequest, error) {
	// Read and parse the request body with size limit to prevent DoS
	body, err := io.ReadAll(io.LimitReader(r.Body, m.getMaxRequestBodySize()))
	if err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, err
	}
	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		m.writeJSONRPCError(w, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, err
	}

	// Validate JSON-RPC 2.0 structure
	if rpcReq.JSONRPC != apidef.JsonRPC20 || rpcReq.Method == "" {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidRequest, mcp.ErrMsgInvalidRequest, nil)
		return nil, fmt.Errorf("invalid JSON-RPC request")
	}

	return &rpcReq, nil
}

// setupJSONRPCRouting stores routing data in context and enables JSON-RPC routing.
// It builds a VEM chain: operation VEM → primitive VEM, allowing middleware to be
// applied at each stage (operation-level middleware, then tool-level middleware).
func (m *MCPJSONRPCMiddleware) setupJSONRPCRouting(r *http.Request, rpcReq *JSONRPCRequest, vemPath, primitive string) {
	// Build VEM chain: [operation VEM, primitive VEM]
	// Operation VEM represents the JSON-RPC method (e.g., "tools/call")
	// Primitive VEM represents the specific tool/resource/prompt
	vemChain := m.buildVEMChain(rpcReq.Method, vemPath)

	// Store parsed data in context
	httpctx.SetJSONRPCRequest(r, &httpctx.JSONRPCRequestData{
		Method:    rpcReq.Method,
		Params:    rpcReq.Params,
		ID:        rpcReq.ID,
		VEMPath:   vemPath,
		Primitive: primitive,
		VEMChain:  vemChain,
	})

	// Enable JSON-RPC routing (allows access to internal VEM endpoints)
	httpctx.SetJsonRPCRouting(r, true)

	// Set loop level to enable internal routing
	ctxSetLoopLevel(r, 1)
	// Ensure limits and quotas apply to MCP routed requests
	ctxSetCheckLoopLimits(r, true)

	// Rewrite URL path to VEM path (final destination)
	r.URL.Path = vemPath
}

// buildVEMChain constructs the chain of VEM paths for middleware application.
// Returns [operation VEM, primitive VEM] to enable sequential middleware application.
func (m *MCPJSONRPCMiddleware) buildVEMChain(method, primitiveVEM string) []string {
	// Build operation VEM based on JSON-RPC method
	operationVEM := m.buildOperationVEM(method)
	if operationVEM == "" {
		// If no operation VEM, just return the primitive VEM
		return []string{primitiveVEM}
	}

	// Return chain: operation first, then primitive
	return []string{operationVEM, primitiveVEM}
}

// buildOperationVEM constructs the operation VEM path for a JSON-RPC method.
// Operation VEMs are JSON-RPC GENERIC - they represent the method name regardless of protocol.
// Format: /json-rpc-method:{method} - works for any JSON-RPC protocol (MCP, A2A, custom, etc.)
func (m *MCPJSONRPCMiddleware) buildOperationVEM(method string) string {
	// GENERIC: Operation VEM is simply the JSON-RPC method name
	// Not MCP-specific - this works for any JSON-RPC protocol
	return jsonrpc.MethodVEMPrefix + method
}

// setupSequentialRouting initializes sequential VEM routing for JSON-RPC requests.
// MCP-SPECIFIC: Contains all MCP protocol knowledge about method types and routing strategy.
//
// Architecture:
// - Operation VEM: JSON-RPC GENERIC (/json-rpc-method:{method}) - works for any JSON-RPC protocol
// - Primitive VEM: MCP-SPECIFIC (/mcp-tool, /mcp-resource, /mcp-prompt) - MCP concepts only
func (m *MCPJSONRPCMiddleware) setupSequentialRouting(r *http.Request, rpcReq *JSONRPCRequest, primitiveVEM, primitiveName string) {
	method := rpcReq.Method

	// Build GENERIC operation VEM: /json-rpc-method:{method}
	// This is protocol-agnostic - works for MCP, A2A, custom JSON-RPC, etc.
	operationVEM := m.buildOperationVEM(method)

	// Determine if MCP primitive routing is needed (2-stage vs 1-stage routing)
	var nextVEM string
	var vemChain []string

	if isPrimitiveInvokingMethod(method) {
		// 2-stage routing: operation VEM → primitive VEM
		nextVEM = primitiveVEM
		vemChain = []string{operationVEM, primitiveVEM}
	} else {
		// 1-stage routing: operation VEM only
		nextVEM = ""
		vemChain = []string{operationVEM}
	}

	// Create generic routing state
	state := &httpctx.JSONRPCRoutingState{
		Method:       method,
		Params:       rpcReq.Params,
		ID:           rpcReq.ID,
		NextVEM:      nextVEM, // What to route to after operation
		OriginalPath: r.URL.Path,
		VEMChain:     vemChain, // For telemetry/debugging
		VisitedVEMs:  []string{},
	}

	httpctx.SetJSONRPCRoutingState(r, state)
	httpctx.SetJsonRPCRouting(r, true)
	ctxSetCheckLoopLimits(r, true)

	// ALWAYS route to operation VEM first via internal redirect
	// Pass check_limits=true to ensure rate limiting is applied at each VEM stage
	ctxSetURLRewriteTarget(r, &url.URL{
		Scheme:   "tyk",
		Host:     "self",
		Path:     operationVEM,
		RawQuery: "check_limits=true",
	})
}

// ProcessRequest handles JSON-RPC request detection and routing.
//
//nolint:staticcheck // ST1008: middleware interface requires (error, int) return order
func (m *MCPJSONRPCMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
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
	vemPath, primitive, found, invalidParams, errMsg := m.routeRequest(rpcReq)
	if invalidParams {
		m.writeJSONRPCError(w, rpcReq.ID, mcp.JSONRPCInvalidParams, errMsg, nil)
		return nil, middleware.StatusRespond
	}
	if !found || vemPath == "" {
		if m.isAllowListEnabled() && !isPrimitiveInvokingMethod(rpcReq.Method) {
			// Route unregistered operations to operation VEM for allowlist enforcement
			m.setupSequentialRouting(r, rpcReq, "", rpcReq.Method)
			return nil, http.StatusOK
		}

		// Unregistered primitives or operations passthrough to upstream per MCP specification
		return nil, http.StatusOK
	}

	// Set up routing context
	m.setupSequentialRouting(r, rpcReq, vemPath, primitive)

	// Return StatusOK to allow chain to continue to DummyProxyHandler, which will handle the redirect
	return nil, http.StatusOK
}

// buildUnregisteredVEMPath constructs a VEM path for an unregistered primitive.
// This path will be caught by the catch-all BlackList VEM when allow list is enabled.
func (m *MCPJSONRPCMiddleware) buildUnregisteredVEMPath(rpcReq *JSONRPCRequest, primitive string) string {
	if prefix, ok := methodPrefixMap[rpcReq.Method]; ok {
		return prefix + primitive
	}
	return ""
}

// routeRequest determines the VEM path for a JSON-RPC request based on its method.
// Returns the VEM path, primitive name, match status, invalid params flag, and error message.
func (m *MCPJSONRPCMiddleware) routeRequest(rpcReq *JSONRPCRequest) (vemPath string, primitive string, found bool, invalidParams bool, errMsg string) {
	primitives := m.Spec.MCPPrimitives

	switch rpcReq.Method {
	case mcp.MethodToolsCall:
		// Extract tool name from params.name
		name, invalid, msg := m.extractAndValidateParam(rpcReq.Params, mcp.ParamKeyName)
		if invalid {
			return "", "", false, true, msg
		}
		vemPath, found = primitives[mcp.PrimitiveKeyTool+name]
		primitive = name

	case mcp.MethodResourcesRead:
		// Extract resource URI from params.uri
		uri, invalid, msg := m.extractAndValidateParam(rpcReq.Params, mcp.ParamKeyURI)
		if invalid {
			return "", "", false, true, msg
		}
		vemPath, found = m.matchResourceURI(uri, primitives)
		primitive = uri

	case mcp.MethodPromptsGet:
		// Extract prompt name from params.name
		name, invalid, msg := m.extractAndValidateParam(rpcReq.Params, mcp.ParamKeyName)
		if invalid {
			return "", "", false, true, msg
		}
		vemPath, found = primitives[mcp.PrimitiveKeyPrompt+name]
		primitive = name

	default:
		// Check for operation-level VEMs (tools/list, initialize, etc.)
		vemPath, found = primitives[mcp.PrimitiveKeyOperation+rpcReq.Method]
		primitive = rpcReq.Method
	}

	// When allowlist is enabled and primitive not found, route to catch-all VEM
	if !found && m.isAllowListEnabled() {
		vemPath = m.buildUnregisteredVEMPath(rpcReq, primitive)
		found = true
	}

	return vemPath, primitive, found, false, ""
}

// ParamExtractionResult represents the result of extracting a parameter from JSON-RPC params.
type ParamExtractionResult struct {
	Value        string
	ErrorMessage string
	IsValid      bool
}

// extractParamWithDetails extracts a string parameter from JSON-RPC params with detailed error info.
// Returns the extraction result with specific error messages for different failure scenarios.
func (m *MCPJSONRPCMiddleware) extractParamWithDetails(params json.RawMessage, key string) ParamExtractionResult {
	if len(params) == 0 {
		return ParamExtractionResult{
			ErrorMessage: mcp.ErrMsgMissingParams,
			IsValid:      false,
		}
	}

	var paramsMap map[string]interface{}
	if err := json.Unmarshal(params, &paramsMap); err != nil {
		return ParamExtractionResult{
			ErrorMessage: mcp.ErrMsgInvalidParamsType,
			IsValid:      false,
		}
	}

	val, exists := paramsMap[key]
	if !exists {
		// Key is missing from params
		errMsg := mcp.ErrMsgInvalidParams
		switch key {
		case mcp.ParamKeyName:
			errMsg = mcp.ErrMsgMissingParamName
		case mcp.ParamKeyURI:
			errMsg = mcp.ErrMsgMissingParamURI
		}
		return ParamExtractionResult{
			ErrorMessage: errMsg,
			IsValid:      false,
		}
	}

	strVal, ok := val.(string)
	if !ok {
		// Value is not a string
		return ParamExtractionResult{
			ErrorMessage: mcp.ErrMsgInvalidParams,
			IsValid:      false,
		}
	}

	if strVal == "" {
		// Value is an empty string
		errMsg := mcp.ErrMsgInvalidParams
		switch key {
		case mcp.ParamKeyName:
			errMsg = mcp.ErrMsgEmptyParamName
		case mcp.ParamKeyURI:
			errMsg = mcp.ErrMsgEmptyParamURI
		}
		return ParamExtractionResult{
			ErrorMessage: errMsg,
			IsValid:      false,
		}
	}

	return ParamExtractionResult{
		Value:   strVal,
		IsValid: true,
	}
}

// extractAndValidateParam extracts a parameter from JSON-RPC params and validates it.
// Returns the parameter value, a flag indicating if the parameter is invalid, and an error message.
func (m *MCPJSONRPCMiddleware) extractAndValidateParam(params json.RawMessage, key string) (value string, invalidParams bool, errMsg string) {
	result := m.extractParamWithDetails(params, key)
	if !result.IsValid {
		return "", true, result.ErrorMessage
	}
	return result.Value, false, ""
}

// matchResourceURI matches a resource URI against configured patterns.
// It first tries an exact match, then falls back to wildcard matching.
func (m *MCPJSONRPCMiddleware) matchResourceURI(uri string, primitives map[string]string) (vemPath string, found bool) {
	// Exact match first
	if path, ok := primitives[mcp.PrimitiveKeyResource+uri]; ok {
		return path, true
	}

	// Wildcard matching with deterministic precedence.
	// Precedence rules:
	// 1. Longer prefix matches beat shorter ones
	// 2. For equal-length prefixes, lexicographically smaller pattern wins
	// Example: "file:///repo/src/*" beats "file:///repo/*" for "file:///repo/src/main.go"
	var bestMatchPattern string
	var bestMatchVEMPath string
	bestMatchPrefixLength := -1

	for primitiveKey, vemPath := range primitives {
		if !strings.HasPrefix(primitiveKey, mcp.PrimitiveKeyResource) {
			continue
		}
		pattern := strings.TrimPrefix(primitiveKey, mcp.PrimitiveKeyResource)
		if m.matchesWildcard(pattern, uri) {
			prefixLen := len(pattern)
			if strings.HasSuffix(pattern, resourceWildcardSuffix) {
				prefixLen = len(strings.TrimSuffix(pattern, "*"))
			}

			if prefixLen > bestMatchPrefixLength || (prefixLen == bestMatchPrefixLength && pattern < bestMatchPattern) {
				bestMatchPattern = pattern
				bestMatchVEMPath = vemPath
				bestMatchPrefixLength = prefixLen
			}
		}
	}

	if bestMatchPrefixLength >= 0 {
		return bestMatchVEMPath, true
	}

	return "", false
}

// matchesWildcard checks if a URI matches a wildcard pattern.
// Supports suffix wildcards: "file:///repo/*" matches "file:///repo/README.md"
func (m *MCPJSONRPCMiddleware) matchesWildcard(pattern, uri string) bool {
	if strings.HasSuffix(pattern, resourceWildcardSuffix) {
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

	w.Header().Set(headerContentType, contentTypeJSON)
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
