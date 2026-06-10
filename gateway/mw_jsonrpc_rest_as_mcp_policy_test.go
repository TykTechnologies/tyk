package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/drl"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/user"
)

func TestRESTAsMCPPolicy_DeniesBlockedToolBeforeSDK(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	called := false
	var err error
	adapterSpec.MCPAdapter.SDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  adapterSpec.Name,
		Tools: adapterSpec.MCPAdapter.UnionTools,
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*mcpadapter.Recorder, error) {
			called = true
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	req := restAsMCPPolicyRequest(t, sessionID, `{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/call",
		"params":{"name":"orders","arguments":{}}
	}`)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, restAsMCPSession("proxy-1", user.AccessDefinition{
		APIID: "proxy-1",
		MCPAccessRights: user.MCPAccessRights{
			Tools: user.AccessControlRules{Blocked: []string{"orders"}},
		},
	}))
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "tool 'orders' is not available")
	assert.False(t, called)
	assert.Equal(t, "tools/call", ctxGetMCPMethod(req))
	assert.Equal(t, "tool", ctxGetMCPPrimitiveType(req))
	assert.Equal(t, "orders", ctxGetMCPPrimitiveName(req))
}

func TestRESTAsMCPPolicy_MethodDeniedBeforeSDK(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	req := restAsMCPPolicyRequest(t, sessionID, `{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/list",
		"params":{}
	}`)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, restAsMCPSession("proxy-1", user.AccessDefinition{
		APIID: "proxy-1",
		JSONRPCMethodsAccessRights: user.AccessControlRules{
			Blocked: []string{"tools/list"},
		},
	}))
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "method 'tools/list' is not available")
}

func TestRESTAsMCPPolicy_FiltersToolsListResponseForCallerView(t *testing.T) {
	gw, adapterSpec := restAsMCPPolicyGatewayWithTwoTools(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	req := restAsMCPPolicyRequest(t, sessionID, `{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/list",
		"params":{}
	}`)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, restAsMCPSession("proxy-1", user.AccessDefinition{
		APIID: "proxy-1",
		MCPAccessRights: user.MCPAccessRights{
			Tools: user.AccessControlRules{Allowed: []string{"orders"}},
		},
	}))
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, rec.Code)
	tools := jsonRPCToolsList(t, rec.Body.Bytes())
	assert.Equal(t, []string{"orders"}, tools)
	assert.NotContains(t, rec.Body.String(), "make_order")
}

func TestRESTAsMCPPolicy_EndpointRateLimitBlocksToolCall(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	cfg := config.Default
	drlManager := &drl.DRL{RequestTokenValue: 1}
	drlManager.SetCurrentTokenValue(1)
	gw.SessionLimiter = NewSessionLimiter(t.Context(), &cfg, drlManager, &cfg.ExternalServices)
	gw.limitHeaderFactory = rate.NewSenderFactory(cfg.RateLimitResponseHeaders)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	session := restAsMCPSession("proxy-1", user.AccessDefinition{
		APIID: "proxy-1",
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "orders", Limit: user.RateLimit{Rate: 1, Per: 60}},
		},
	})
	NormalizeMCPEndpoints(session)

	makeRequest := func() *http.Request {
		req := restAsMCPPolicyRequest(t, sessionID, `{
			"jsonrpc":"2.0",
			"id":2,
			"method":"tools/call",
			"params":{"name":"orders","arguments":{}}
		}`)
		ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
		setSessionForTest(req, session)
		return req
	}

	first := httptest.NewRecorder()
	err, status := mw.ProcessRequest(first, makeRequest(), nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, first.Code)

	second := httptest.NewRecorder()
	err, status = mw.ProcessRequest(second, makeRequest(), nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Contains(t, second.Body.String(), "Rate Limit Exceeded")
}

func TestRESTAsMCPPolicy_AliasUsesCallerFacingName(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	req := restAsMCPPolicyRequest(t, sessionID, `{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/call",
		"params":{"name":"orders","arguments":{}}
	}`)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, restAsMCPSession("proxy-1", user.AccessDefinition{
		APIID: "proxy-1",
		MCPAccessRights: user.MCPAccessRights{
			Tools: user.AccessControlRules{Allowed: []string{"list_orders"}},
		},
	}))
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "tool 'orders' is not available")
}

func TestRESTAsMCPPolicy_RejectsOversizedJSONRPCBeforeSDK(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	called := false
	var err error
	adapterSpec.MCPAdapter.SDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  adapterSpec.Name,
		Tools: adapterSpec.MCPAdapter.UnionTools,
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*mcpadapter.Recorder, error) {
			called = true
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-1")
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"orders","arguments":{"payload":"` +
		strings.Repeat("x", syntheticJSONRPCMethodReadLimit) +
		`"}}}`
	req := restAsMCPPolicyRequest(t, sessionID, body)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, restAsMCPSession("proxy-1", user.AccessDefinition{APIID: "proxy-1"}))
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), mcp.ErrMsgParseError)
	assert.False(t, called)
}

func restAsMCPPolicyGatewayWithTwoTools(t *testing.T) (*Gateway, *APISpec) {
	t.Helper()

	rest := restSourceSpec("rest-1", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Allow: boolPtr(true)},
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Name: "make_order", Allow: boolPtr(true)},
		},
	})
	adapterSpec, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, nil)
	require.NoError(t, err)

	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"rest-1":          rest,
			adapterSpec.APIID: adapterSpec,
			"proxy-1":         proxy,
		},
		apisHandlesByID: &sync.Map{},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})})
	snapshot, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(snapshot)
	return gw, adapterSpec
}

func restAsMCPPolicyRequest(t *testing.T, sessionID, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)
	return req
}

func restAsMCPSession(apiID string, accessDef user.AccessDefinition) *user.SessionState {
	return &user.SessionState{
		KeyID: "agent-key-1",
		AccessRights: map[string]user.AccessDefinition{
			apiID: accessDef,
		},
	}
}

func jsonRPCToolsList(t *testing.T, body []byte) []string {
	t.Helper()

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	result := envelope["result"].(map[string]any)
	rawTools := result["tools"].([]any)
	names := make([]string, 0, len(rawTools))
	for _, raw := range rawTools {
		tool := raw.(map[string]any)
		names = append(names, tool["name"].(string))
	}
	return names
}
