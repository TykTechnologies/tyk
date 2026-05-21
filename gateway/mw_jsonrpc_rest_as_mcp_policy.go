package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/user"
)

const (
	mcpListFilterTools             = "tools"
	mcpListFilterPrompts           = "prompts"
	mcpListFilterResources         = "resources"
	mcpListFilterResourceTemplates = "resourceTemplates"

	jsonrpcRateLimitExceededMessage = "Rate Limit Exceeded"
	jsonrpcInternalErrorMessage     = "Internal Server Error"
)

type restAsMCPPolicyContext struct {
	proxyAPIID string
	proxySpec  *APISpec
	session    *user.SessionState
	accessDef  user.AccessDefinition
	hasAccess  bool
	rpcReq     *JSONRPCRequest
	route      jsonrpc.RouteResult
	listConfig *mcp.ListFilterConfig
}

func (m *JSONRPCMiddleware) serveSyntheticMCPAdapter(w http.ResponseWriter, r *http.Request) {
	policyCtx, responded := m.prepareRESTAsMCPPolicy(w, r)
	if responded {
		return
	}

	ensureMCPStreamableAccept(r)
	handler := m.Spec.MCPSDKAdapter.StreamableHTTPHandler(nil)

	if policyCtx == nil || policyCtx.listConfig == nil {
		handler.ServeHTTP(w, r)
		return
	}

	capture := newCapturedResponseWriter()
	handler.ServeHTTP(capture, r)
	m.rewriteRESTAsMCPToolListForProxy(policyCtx, capture)
	policyCtx.filterListResponse(capture)
	capture.flushTo(w)
}

func (m *JSONRPCMiddleware) prepareRESTAsMCPPolicy(w http.ResponseWriter, r *http.Request) (*restAsMCPPolicyContext, bool) {
	rpcReq, ok := m.parseSyntheticAdapterJSONRPC(r)
	if !ok {
		return nil, false
	}

	route, responded := m.routeSyntheticAdapterJSONRPC(w, r, rpcReq)
	if responded {
		return nil, true
	}

	policyCtx := &restAsMCPPolicyContext{rpcReq: rpcReq, route: route}
	policyCtx.setJSONRPCState(r)
	m.loadRESTAsMCPPolicyCaller(r, policyCtx)

	if !m.deniesRESTAsMCPPolicies(w, r, policyCtx) {
		policyCtx.listConfig = listConfigForMCPMethod(rpcReq.Method)
		return policyCtx, false
	}

	return policyCtx, true
}

func (m *JSONRPCMiddleware) loadRESTAsMCPPolicyCaller(r *http.Request, policyCtx *restAsMCPPolicyContext) {
	proxyAPIID := httpctx.GetMCPProxyCallerAPIID(r)
	if proxyAPIID == "" || m.Gw == nil {
		return
	}

	policyCtx.proxyAPIID = proxyAPIID
	policyCtx.proxySpec = m.Gw.getApiSpec(proxyAPIID)
	policyCtx.session = ctxGetSession(r)
	if policyCtx.proxySpec == nil || policyCtx.session == nil {
		return
	}

	accessDef, found := policyCtx.session.AccessRights[proxyAPIID]
	if !found {
		return
	}

	policyCtx.accessDef = accessDef
	policyCtx.hasAccess = true
}

func (m *JSONRPCMiddleware) deniesRESTAsMCPPolicies(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext) bool {
	if m.deniesRESTAsMCPMethod(w, r, policyCtx) {
		return true
	}
	if m.deniesRESTAsMCPPrimitive(w, r, policyCtx) {
		return true
	}
	if m.enforceRESTAsMCPEndpointRateLimits(w, r, policyCtx) {
		return true
	}
	return false
}

func (m *JSONRPCMiddleware) routeSyntheticAdapterJSONRPC(w http.ResponseWriter, r *http.Request, rpcReq *JSONRPCRequest) (jsonrpc.RouteResult, bool) {
	router := m.Spec.JSONRPCRouter
	if router == nil {
		router = mcp.NewRouter()
	}

	result, err := router.RouteMethod(rpcReq.Method, rpcReq.Params, m.Spec.MCPPrimitives)
	if err != nil {
		m.writeJSONRPCError(w, r, rpcReq.ID, mcp.JSONRPCInvalidParams, err.Error(), nil)
		return jsonrpc.RouteResult{}, true
	}

	return result, false
}

func (m *JSONRPCMiddleware) parseSyntheticAdapterJSONRPC(r *http.Request) (*JSONRPCRequest, bool) {
	if r.Method != http.MethodPost {
		return nil, false
	}
	if !strings.HasPrefix(r.Header.Get(headerContentType), contentTypeJSON) {
		return nil, false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		return nil, false
	}
	if rpcReq.Method == "" {
		return nil, false
	}

	return &rpcReq, true
}

func (c *restAsMCPPolicyContext) setJSONRPCState(r *http.Request) {
	primitiveType := primitiveTypeForMethod(c.rpcReq.Method)

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method:        c.rpcReq.Method,
		Params:        c.rpcReq.Params,
		ID:            c.rpcReq.ID,
		OriginalPath:  r.URL.Path,
		VEMChain:      c.route.VEMChain,
		PrimitiveType: primitiveType,
		PrimitiveName: c.route.PrimitiveName,
	})

	ctxSetMCPMethod(r, c.rpcReq.Method)
	ctxSetMCPPrimitiveType(r, primitiveType)
	ctxSetMCPPrimitiveName(r, c.route.PrimitiveName)
}

func (m *JSONRPCMiddleware) deniesRESTAsMCPMethod(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext) bool {
	if !policyCtx.hasAccess || policyCtx.accessDef.JSONRPCMethodsAccessRights.IsEmpty() {
		return false
	}
	if !mcp.CheckAccessControlRules(policyCtx.accessDef.JSONRPCMethodsAccessRights, policyCtx.rpcReq.Method) {
		return false
	}

	writeJSONRPCAccessDenied(w, r, fmt.Sprintf("method '%s' is not available", policyCtx.rpcReq.Method))
	return true
}

func (m *JSONRPCMiddleware) deniesRESTAsMCPPrimitive(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext) bool {
	if !policyCtx.hasAccess || policyCtx.accessDef.MCPAccessRights.IsEmpty() {
		return false
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil || state.PrimitiveType == "" || state.PrimitiveName == "" {
		return false
	}

	rules := rulesForPrimitiveType(policyCtx.accessDef.MCPAccessRights, state.PrimitiveType)
	if !mcp.CheckAccessControlRules(rules, state.PrimitiveName) {
		return false
	}

	writeJSONRPCAccessDenied(w, r, fmt.Sprintf("%s '%s' is not available", state.PrimitiveType, state.PrimitiveName))
	return true
}

func (m *JSONRPCMiddleware) enforceRESTAsMCPEndpointRateLimits(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext) bool {
	if !policyCtx.hasAccess {
		return false
	}

	for _, vemPath := range policyCtx.route.VEMChain {
		if m.enforceRESTAsMCPEndpointRateLimit(w, r, policyCtx, vemPath) {
			return true
		}
	}

	return false
}

func (m *JSONRPCMiddleware) enforceRESTAsMCPEndpointRateLimit(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext, vemPath string) bool {
	if m.Gw == nil || m.Gw.SessionLimiter.config == nil || policyCtx.proxySpec == nil || len(policyCtx.accessDef.Endpoints) == 0 {
		return false
	}

	rateReq := restAsMCPRateLimitRequest(r, vemPath)
	if _, ok := m.Gw.SessionLimiter.RateLimitInfo(rateReq, policyCtx.proxySpec, policyCtx.accessDef.Endpoints); !ok {
		return false
	}

	reason := m.Gw.SessionLimiter.ForwardMessage(
		rateReq,
		policyCtx.session,
		restAsMCPRateLimitKey(r, policyCtx),
		"",
		true,
		false,
		policyCtx.proxySpec,
		false,
		restAsMCPRateLimitHeaderSender(m.Gw, w),
	)

	return writeRESTAsMCPRateLimitResult(w, policyCtx.rpcReq.ID, reason)
}

func restAsMCPRateLimitRequest(r *http.Request, vemPath string) *http.Request {
	rateReq := r.Clone(r.Context())
	copiedURL := *r.URL
	copiedURL.Path = vemPath
	copiedURL.RawPath = ""
	rateReq.URL = &copiedURL
	rateReq.Method = http.MethodPost
	return rateReq
}

func restAsMCPRateLimitKey(r *http.Request, policyCtx *restAsMCPPolicyContext) string {
	if token := ctxGetAuthToken(r); token != "" {
		return token
	}
	return policyCtx.session.KeyID
}

func restAsMCPRateLimitHeaderSender(gw *Gateway, w http.ResponseWriter) rate.HeaderSender {
	if gw.limitHeaderFactory == nil {
		return nil
	}
	return gw.limitHeaderFactory(w.Header())
}

func writeRESTAsMCPRateLimitResult(w http.ResponseWriter, requestID any, reason sessionFailReason) bool {
	switch reason {
	case sessionFailNone:
		return false
	case sessionFailRateLimit:
		jsonrpcerrors.WriteJSONRPCError(w, requestID, http.StatusTooManyRequests, jsonrpcRateLimitExceededMessage)
		return true
	default:
		jsonrpcerrors.WriteJSONRPCError(w, requestID, http.StatusInternalServerError, jsonrpcInternalErrorMessage)
		return true
	}
}

func listConfigForMCPMethod(method string) *mcp.ListFilterConfig {
	switch method {
	case mcp.MethodToolsList:
		return mcp.ListFilterConfigs[mcpListFilterTools]
	case mcp.MethodPromptsList:
		return mcp.ListFilterConfigs[mcpListFilterPrompts]
	case mcp.MethodResourcesList:
		return mcp.ListFilterConfigs[mcpListFilterResources]
	case mcp.MethodResourcesTemplatesList:
		return mcp.ListFilterConfigs[mcpListFilterResourceTemplates]
	default:
		return nil
	}
}

func (c *restAsMCPPolicyContext) filterListResponse(res *capturedResponseWriter) {
	if !c.hasAccess || c.listConfig == nil || c.accessDef.MCPAccessRights.IsEmpty() {
		return
	}

	rules := c.listConfig.RulesFrom(c.accessDef.MCPAccessRights)
	if rules.IsEmpty() {
		return
	}

	body, ok := mcp.FilterJSONRPCBody(res.body.Bytes(), c.listConfig, rules)
	if !ok {
		return
	}

	res.body.Reset()
	res.body.Write(body)
	res.header.Set("Content-Length", strconv.Itoa(len(body)))
}

func (m *JSONRPCMiddleware) rewriteRESTAsMCPToolListForProxy(policyCtx *restAsMCPPolicyContext, res *capturedResponseWriter) {
	if m == nil || m.Spec == nil || policyCtx == nil || policyCtx.rpcReq == nil {
		return
	}
	if policyCtx.rpcReq.Method != mcp.MethodToolsList || policyCtx.proxyAPIID == "" || len(m.Spec.MCPProxyToolViews) == 0 {
		return
	}

	view, ok := m.Spec.MCPProxyToolViews[policyCtx.proxyAPIID]
	if !ok {
		return
	}

	body, ok := toolListBodyForView(res.body.Bytes(), view)
	if !ok {
		return
	}

	res.body.Reset()
	res.body.Write(body)
	res.header.Set("Content-Length", strconv.Itoa(len(body)))
}

func toolListBodyForView(body []byte, view oas.MCPToolView) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}

	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	result, ok := env["result"].(map[string]any)
	if !ok {
		return nil, false
	}

	tools := make([]any, 0, len(view.Tools))
	for _, tool := range view.Tools {
		tools = append(tools, toolListEntry(tool))
	}
	result["tools"] = tools

	rewritten, err := json.Marshal(env)
	if err != nil {
		return nil, false
	}
	return rewritten, true
}

func toolListEntry(tool oas.DerivedTool) map[string]any {
	entry := map[string]any{
		"name":        tool.Name,
		"inputSchema": tool.InputSchema,
	}
	if entry["inputSchema"] == nil {
		entry["inputSchema"] = map[string]any{"type": "object"}
	}
	if tool.Description != "" {
		entry["description"] = tool.Description
	}
	return entry
}

type capturedResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newCapturedResponseWriter() *capturedResponseWriter {
	return &capturedResponseWriter{header: make(http.Header)}
}

func (w *capturedResponseWriter) Header() http.Header {
	return w.header
}

func (w *capturedResponseWriter) WriteHeader(statusCode int) {
	if w.status == 0 {
		w.status = statusCode
	}
}

func (w *capturedResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}

func (w *capturedResponseWriter) flushTo(dst http.ResponseWriter) {
	copyCapturedHeader(dst.Header(), w.header)
	if w.status != 0 {
		dst.WriteHeader(w.status)
	}
	if _, err := dst.Write(w.body.Bytes()); err != nil {
		log.WithError(err).Error("Failed to write REST-as-MCP filtered response")
	}
}

func copyCapturedHeader(dst, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
