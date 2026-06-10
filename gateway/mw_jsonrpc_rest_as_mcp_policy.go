package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/jsonrpc"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/user"
)

const (
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
	listConfig *mcp.ListFilterConfig
}

// prepareRESTAsMCPPolicy parses the JSON-RPC request handled by a synthetic
// REST-as-MCP adapter and applies caller-proxy policy before SDK execution.
func (m *JSONRPCMiddleware) prepareRESTAsMCPPolicy(w http.ResponseWriter, r *http.Request) (*restAsMCPPolicyContext, bool) {
	rpcReq, ok, err := parseSyntheticAdapterJSONRPC(r)
	if err != nil {
		m.writeJSONRPCError(w, r, nil, mcp.JSONRPCParseError, mcp.ErrMsgParseError, nil)
		return nil, true
	}
	if !ok {
		return nil, false
	}

	route, err := m.routeSyntheticAdapterJSONRPC(rpcReq)
	if err != nil {
		m.writeJSONRPCError(w, r, rpcReq.ID, mcp.JSONRPCInvalidParams, err.Error(), nil)
		return nil, true
	}

	policyCtx := &restAsMCPPolicyContext{
		rpcReq:     rpcReq,
		listConfig: listConfigForMCPMethod(rpcReq.Method),
	}
	policyCtx.setJSONRPCState(r, route.VEMChain, route.PrimitiveName)
	m.loadRESTAsMCPPolicyCaller(r, policyCtx)

	if m.deniesRESTAsMCPPolicies(w, r, policyCtx) {
		return policyCtx, true
	}

	return policyCtx, false
}

func parseSyntheticAdapterJSONRPC(r *http.Request) (*JSONRPCRequest, bool, error) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		return nil, false, nil
	}
	if !strings.HasPrefix(r.Header.Get(headerContentType), contentTypeJSON) {
		return nil, false, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, syntheticJSONRPCMethodReadLimit+1))
	r.Body = prefixedReadCloser{
		Reader: io.MultiReader(bytes.NewReader(body), r.Body),
		Closer: r.Body,
	}
	if err != nil {
		return nil, false, err
	}
	if len(body) > syntheticJSONRPCMethodReadLimit {
		return nil, false, fmt.Errorf("synthetic JSON-RPC request exceeds %d bytes", syntheticJSONRPCMethodReadLimit)
	}

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil || rpcReq.Method == "" {
		return nil, false, nil
	}

	return &rpcReq, true, nil
}

func (m *JSONRPCMiddleware) routeSyntheticAdapterJSONRPC(rpcReq *JSONRPCRequest) (jsonrpc.RouteResult, error) {
	router := m.Spec.JSONRPCRouter
	if router == nil {
		router = mcp.NewRouter()
	}

	result, err := router.RouteMethod(rpcReq.Method, rpcReq.Params, m.Spec.MCPPrimitives)
	if err != nil {
		return jsonrpc.RouteResult{}, err
	}
	return result, nil
}

func (c *restAsMCPPolicyContext) setJSONRPCState(r *http.Request, vemChain []string, primitiveName string) {
	primitiveType := primitiveTypeForMethod(c.rpcReq.Method)
	httpctx.SetJSONRPCRoutingState(r, &httpctx.JSONRPCRoutingState{
		Method:        c.rpcReq.Method,
		Params:        c.rpcReq.Params,
		ID:            c.rpcReq.ID,
		OriginalPath:  r.URL.Path,
		VEMChain:      vemChain,
		PrimitiveType: primitiveType,
		PrimitiveName: primitiveName,
	})
	httpctx.SetJsonRPCRouting(r, true)

	ctxSetMCPMethod(r, c.rpcReq.Method)
	ctxSetMCPPrimitiveType(r, primitiveType)
	ctxSetMCPPrimitiveName(r, primitiveName)
}

func (m *JSONRPCMiddleware) loadRESTAsMCPPolicyCaller(r *http.Request, policyCtx *restAsMCPPolicyContext) {
	proxyAPIID := ctxGetMCPAdapterCallerProxyID(r)
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
	return m.enforceRESTAsMCPEndpointRateLimits(w, r, policyCtx)
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
	if !policyCtx.hasAccess || policyCtx.proxySpec == nil || m.Gw == nil || m.Gw.SessionLimiter.config == nil {
		return false
	}

	state := httpctx.GetJSONRPCRoutingState(r)
	if state == nil {
		return false
	}

	for _, vemPath := range state.VEMChain {
		if m.enforceRESTAsMCPEndpointRateLimit(w, r, policyCtx, vemPath) {
			return true
		}
	}
	return false
}

func (m *JSONRPCMiddleware) enforceRESTAsMCPEndpointRateLimit(w http.ResponseWriter, r *http.Request, policyCtx *restAsMCPPolicyContext, vemPath string) bool {
	if len(policyCtx.accessDef.Endpoints) == 0 {
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

func filterRESTAsMCPListResponse(body []byte, policyCtx *restAsMCPPolicyContext) ([]byte, bool) {
	if policyCtx == nil || policyCtx.proxySpec == nil || policyCtx.session == nil || policyCtx.listConfig == nil {
		return nil, false
	}

	ruleSets := effectiveMCPListRuleSets(policyCtx.proxySpec, policyCtx.session, policyCtx.listConfig)
	if len(ruleSets) == 0 {
		return nil, false
	}

	return mcp.FilterJSONRPCBodyWithRuleSets(body, policyCtx.listConfig, ruleSets)
}
