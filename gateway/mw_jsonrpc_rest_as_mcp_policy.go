package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/user"
)

type restAsMCPPolicyContext struct {
	proxyAPIID string
	proxySpec  *APISpec
	session    *user.SessionState
	accessDef  user.AccessDefinition
	hasAccess  bool
	rpcReq     *JSONRPCRequest
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
	policyCtx.filterListResponse(capture)
	capture.flushTo(w)
}

func (m *JSONRPCMiddleware) prepareRESTAsMCPPolicy(w http.ResponseWriter, r *http.Request) (*restAsMCPPolicyContext, bool) {
	rpcReq, ok := m.parseSyntheticAdapterJSONRPC(r)
	if !ok {
		return nil, false
	}

	policyCtx := &restAsMCPPolicyContext{rpcReq: rpcReq}
	policyCtx.setJSONRPCState(r)

	proxyAPIID := httpctx.GetMCPProxyCallerAPIID(r)
	if proxyAPIID == "" || m.Gw == nil {
		return policyCtx, false
	}

	policyCtx.proxyAPIID = proxyAPIID
	policyCtx.proxySpec = m.Gw.getApiSpec(proxyAPIID)
	policyCtx.session = ctxGetSession(r)
	if policyCtx.proxySpec == nil || policyCtx.session == nil {
		return policyCtx, false
	}

	accessDef, found := policyCtx.session.AccessRights[proxyAPIID]
	if !found {
		return policyCtx, false
	}
	policyCtx.accessDef = accessDef
	policyCtx.hasAccess = true

	if m.deniesRESTAsMCPMethod(w, r, policyCtx) {
		return policyCtx, true
	}
	if m.deniesRESTAsMCPPrimitive(w, r, policyCtx) {
		return policyCtx, true
	}
	if m.enforceRESTAsMCPEndpointRateLimits(w, r, policyCtx) {
		return policyCtx, true
	}

	policyCtx.listConfig = listConfigForMCPMethod(rpcReq.Method)
	return policyCtx, false
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
	primitiveName := primitiveNameForMethod(c.rpcReq.Method, c.rpcReq.Params)

	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method:        c.rpcReq.Method,
		Params:        c.rpcReq.Params,
		ID:            c.rpcReq.ID,
		OriginalPath:  r.URL.Path,
		PrimitiveType: primitiveType,
		PrimitiveName: primitiveName,
	})

	ctxSetMCPMethod(r, c.rpcReq.Method)
	ctxSetMCPPrimitiveType(r, primitiveType)
	ctxSetMCPPrimitiveName(r, primitiveName)
}

func primitiveNameForMethod(method string, params json.RawMessage) string {
	switch method {
	case mcp.MethodToolsCall, mcp.MethodPromptsGet:
		return stringParam(params, mcp.ParamKeyName)
	case mcp.MethodResourcesRead:
		return stringParam(params, mcp.ParamKeyURI)
	default:
		return method
	}
}

func stringParam(params json.RawMessage, key string) string {
	if len(params) == 0 {
		return ""
	}

	var obj map[string]any
	if err := json.Unmarshal(params, &obj); err != nil {
		return ""
	}
	if val, ok := obj[key].(string); ok {
		return val
	}
	return ""
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
	if m.enforceRESTAsMCPEndpointRateLimit(w, r, policyCtx, jsonrpc.MethodVEMPrefix+policyCtx.rpcReq.Method) {
		return true
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil || state.PrimitiveType == "" || state.PrimitiveName == "" {
		return false
	}

	prefix := vemPrefixForPrimitiveType(state.PrimitiveType)
	if prefix == "" {
		return false
	}

	return m.enforceRESTAsMCPEndpointRateLimit(w, r, policyCtx, prefix+state.PrimitiveName)
}

func (m *JSONRPCMiddleware) enforceRESTAsMCPEndpointRateLimit(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext, vemPath string) bool {
	if m.Gw == nil || m.Gw.SessionLimiter.config == nil || policyCtx.proxySpec == nil || len(policyCtx.accessDef.Endpoints) == 0 {
		return false
	}

	rateReq := r.Clone(r.Context())
	copiedURL := *r.URL
	copiedURL.Path = vemPath
	copiedURL.RawPath = ""
	rateReq.URL = &copiedURL
	rateReq.Method = http.MethodPost

	if _, ok := m.Gw.SessionLimiter.RateLimitInfo(rateReq, policyCtx.proxySpec, policyCtx.accessDef.Endpoints); !ok {
		return false
	}

	rateLimitKey := ctxGetAuthToken(r)
	if rateLimitKey == "" {
		rateLimitKey = policyCtx.session.KeyID
	}

	var sender rate.HeaderSender
	if m.Gw.limitHeaderFactory == nil {
		sender = nil
	} else {
		sender = m.Gw.limitHeaderFactory(w.Header())
	}

	reason := m.Gw.SessionLimiter.ForwardMessage(
		rateReq,
		policyCtx.session,
		rateLimitKey,
		"",
		true,
		false,
		policyCtx.proxySpec,
		false,
		sender,
	)

	switch reason {
	case sessionFailNone:
		return false
	case sessionFailRateLimit:
		jsonrpcerrors.WriteJSONRPCError(w, policyCtx.rpcReq.ID, http.StatusTooManyRequests, "Rate Limit Exceeded")
		return true
	default:
		jsonrpcerrors.WriteJSONRPCError(w, policyCtx.rpcReq.ID, http.StatusInternalServerError, "Internal Server Error")
		return true
	}
}

func listConfigForMCPMethod(method string) *mcp.ListFilterConfig {
	switch method {
	case mcp.MethodToolsList:
		return mcp.ListFilterConfigs["tools"]
	case mcp.MethodPromptsList:
		return mcp.ListFilterConfigs["prompts"]
	case mcp.MethodResourcesList:
		return mcp.ListFilterConfigs["resources"]
	case mcp.MethodResourcesTemplatesList:
		return mcp.ListFilterConfigs["resourceTemplates"]
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
