package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/otel"
	otelmcp "github.com/TykTechnologies/tyk/internal/otel/mcp"
)

const (
	contentTypeJSON         = "application/json"
	headerContentType       = "Content-Type"
	httpHeaderContentLength = "Content-Length"
)

const syntheticJSONRPCMethodReadLimit = 1 << 20

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
// Returns the parsed request and the raw body, or writes an error response and
// returns nil. The raw body is returned so callers (e.g. the trace-context
// read) can resolve a configured body path without re-reading the request.
// Request body size limits are enforced at the gateway level (proxy_muxer).
func (m *JSONRPCMiddleware) readAndParseJSONRPC(w http.ResponseWriter, r *http.Request) (*JSONRPCRequest, []byte, error) {
	// Read the request body (already size-limited by gateway if configured)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		m.writeJSONRPCError(w, r, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, nil, err
	}
	// Restore body for upstream
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		m.writeJSONRPCError(w, r, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, nil, err
	}

	// Validate JSON-RPC 2.0 structure
	if rpcReq.JSONRPC != apidef.JsonRPC20 || rpcReq.Method == "" {
		m.writeJSONRPCError(w, r, rpcReq.ID, mcp.JSONRPCInvalidRequest, mcp.ErrMsgInvalidRequest, nil)
		return nil, nil, fmt.Errorf("invalid JSON-RPC request")
	}

	return &rpcReq, body, nil
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

	if m.Spec.IsSyntheticMCPAdapter() {
		return m.processSyntheticMCPAdapterRequest(w, r)
	}

	// Validate request type
	if !m.validateJSONRPCRequest(r) {
		return nil, http.StatusOK
	}

	// Parse JSON-RPC request
	rpcReq, body, err := m.readAndParseJSONRPC(w, r)
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

	// Bridge the MCP trace context (SEP-414): join the agent's trace from the
	// configured read sources and stamp the method/tool on the span.
	m.bridgeMCPTraceContext(r, rpcReq, body)

	// Return StatusOK to allow chain to continue to DummyProxyHandler, which will handle the redirect
	return nil, http.StatusOK
}

// bridgeMCPTraceContext reads the W3C trace context from the configured sources
// and, when the agent set it only in the body (no HTTP traceparent), installs
// it into the request context so every span/log/audit Tyk emits later joins the
// agent's trace. It then writes the current trace context into the outbound
// body's trace-context field so the MCP server — which reads the body, not the
// header — joins the trace too: the body-channel equivalent of the traceparent
// header Tyk already injects upstream for ordinary HTTP. It also stamps the MCP
// method/tool and trace_source on the span. No-op when tracing is disabled.
func (m *JSONRPCMiddleware) bridgeMCPTraceContext(r *http.Request, rpcReq *JSONRPCRequest, body []byte) {
	if m.Gw == nil {
		return
	}
	cfg := m.Gw.GetConfig()
	if !cfg.OpenTelemetry.TracesEnabled() {
		return
	}

	sources := cfg.OpenTelemetry.MCPTraceContext().ReadSources
	if len(sources) == 0 {
		sources = otel.DefaultMCPReadSources()
	}

	source := otel.JoinMCPTraceContext(r, sources, body)
	ctxSetSpanAttributes(r, m.Name(), otel.MCPSpanAttributes(rpcReq.Method, ctxGetMCPPrimitiveType(r), ctxGetMCPPrimitiveName(r), source)...)

	m.writeMCPTraceContext(r, body)
}

// writeMCPTraceContext rewrites the outbound MCP body so its trace-context field
// carries Tyk's current W3C trace context (SEP-414): the downstream MCP server
// then joins the trace and nests under Tyk. It is the body-channel parallel of
// the traceparent header the OTel roundtripper injects for ordinary upstreams,
// so it runs automatically whenever tracing is enabled. A no-op — body forwarded
// unchanged — when there is no active context or the body is non-MCP/malformed.
func (m *JSONRPCMiddleware) writeMCPTraceContext(r *http.Request, body []byte) {
	out, changed := otelmcp.WriteMetaTraceContext(body, otel.CurrentTraceContext(r.Context()))
	if !changed {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(out))
	r.ContentLength = int64(len(out))
	r.Header.Set(httpHeaderContentLength, strconv.Itoa(len(out)))
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

//nolint:staticcheck // ST1008: middleware helper mirrors ProcessRequest's (error, int) convention.
func (m *JSONRPCMiddleware) processSyntheticMCPAdapterRequest(w http.ResponseWriter, r *http.Request) (error, int) {
	if m.Spec == nil || m.Spec.MCPAdapter.SDKAdapter == nil {
		http.Error(w, "REST-as-MCP adapter is not initialized", http.StatusInternalServerError)
		return nil, middleware.StatusRespond
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil, middleware.StatusRespond
	}

	method := syntheticJSONRPCMethod(r)
	normaliseMCPStreamableAccept(r)
	installMCPAdapterCallContext(r, m.Gw, m.Spec)

	if method == mcp.MethodToolsList {
		rec := newBufferedResponseWriter()
		m.Spec.MCPAdapter.SDKAdapter.StreamableHTTPHandler(nil).ServeHTTP(rec, r)
		view, ok := m.syntheticMCPToolViewForCaller(r)
		m.writeSyntheticMCPToolsListResponse(w, r, rec, view, ok)
		return nil, middleware.StatusRespond
	}

	m.Spec.MCPAdapter.SDKAdapter.StreamableHTTPHandler(nil).ServeHTTP(w, r)
	return nil, middleware.StatusRespond
}

func syntheticJSONRPCMethod(r *http.Request) string {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return ""
	}
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil && state.Method != "" {
		return state.Method
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, syntheticJSONRPCMethodReadLimit+1))
	r.Body = prefixedReadCloser{
		Reader: io.MultiReader(bytes.NewReader(body), r.Body),
		Closer: r.Body,
	}
	if err != nil {
		return ""
	}
	if len(body) > syntheticJSONRPCMethodReadLimit {
		return ""
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return req.Method
}

type prefixedReadCloser struct {
	io.Reader
	io.Closer
}

func normaliseMCPStreamableAccept(r *http.Request) {
	if r == nil {
		return
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && strings.Contains(accept, "text/event-stream") {
		return
	}
	r.Header.Set("Accept", "application/json, text/event-stream")
}

func (m *JSONRPCMiddleware) syntheticMCPToolViewForCaller(r *http.Request) (oas.MCPToolView, bool) {
	callerProxyID := ctxGetMCPAdapterCallerProxyID(r)
	if callerProxyID == "" || m.Spec == nil || m.Spec.MCPAdapter.ToolViews == nil {
		return oas.MCPToolView{}, false
	}
	view, ok := m.Spec.MCPAdapter.ToolViews[callerProxyID]
	return view, ok
}

func (m *JSONRPCMiddleware) writeSyntheticMCPToolsListResponse(w http.ResponseWriter, r *http.Request, rec *bufferedResponseWriter, view oas.MCPToolView, filter bool) {
	body := rec.body.Bytes()
	if filter && rec.statusCode < http.StatusBadRequest {
		rewritten, err := rewriteMCPToolsListResponse(body, view)
		if err != nil {
			m.Logger().WithError(err).Warn("failed to rewrite REST-as-MCP tools/list response")
			m.writeJSONRPCError(w, r, nil, mcp.JSONRPCInternalError, "Internal error", nil)
			return
		}
		body = rewritten
	}
	rec.writeTo(w, body)
}

func rewriteMCPToolsListResponse(body []byte, view oas.MCPToolView) ([]byte, error) {
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		return body, nil
	}
	result["tools"] = view.Tools
	return json.Marshal(envelope)
}

type bufferedResponseWriter struct {
	header      http.Header
	body        bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{
		header:     http.Header{},
		statusCode: http.StatusOK,
	}
}

func (w *bufferedResponseWriter) Header() http.Header {
	return w.header
}

func (w *bufferedResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = statusCode
	w.wroteHeader = true
}

func (w *bufferedResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(data)
}

func (w *bufferedResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
}

func (w *bufferedResponseWriter) writeTo(dst http.ResponseWriter, body []byte) {
	for key, values := range w.header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}
	dst.WriteHeader(w.statusCode)
	if _, err := dst.Write(body); err != nil {
		log.WithError(err).Debug("failed to write REST-as-MCP response")
	}
}
