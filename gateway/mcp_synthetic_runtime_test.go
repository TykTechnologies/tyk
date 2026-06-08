package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

func TestResolveInternalHTTPHandlerForMCPAdapterLoop_StampsCallerAndUsesCanonicalAdapter(t *testing.T) {
	gw := &Gateway{
		apisByID:        map[string]*APISpec{},
		apisHandlesByID: &sync.Map{},
	}
	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	caller := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	gw.apisByID[adapterSpec.APIID] = adapterSpec

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	gw.apisHandlesByID.Store(adapterSpec.APIID, &ChainObject{ThisHandler: handler})

	req := httptest.NewRequest(http.MethodPost, "/proxy/mcp", nil)
	gotHandler, target, ok := gw.findInternalHTTPHandlerForLoop("rest-1", caller, req)
	require.True(t, ok)
	assert.Equal(t, adapterSpec, target)
	assert.Equal(t, "proxy-1", ctxGetMCPAdapterCallerProxyID(req))

	rec := httptest.NewRecorder()
	gotHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code)
}

func TestSyntheticAdapterProcessRequest_UsesSDKAdapter(t *testing.T) {
	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec}}

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body, "result", "response body: %s", rec.Body.String())
	result := body["result"].(map[string]any)
	assert.Equal(t, adapterSpec.APIID, result["serverInfo"].(map[string]any)["name"])
	capabilities := result["capabilities"].(map[string]any)
	tools := capabilities["tools"].(map[string]any)
	assert.NotContains(t, tools, "listChanged")
	assert.NotContains(t, capabilities, "resources")
	assert.NotContains(t, capabilities, "prompts")
}

func TestRESTAsMCPAdapter_RejectsNonPOSTMethods(t *testing.T) {
	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec}}

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/mcp", nil)
			req.Header.Set("Accept", "application/json, text/event-stream")
			rec := httptest.NewRecorder()

			err, status := mw.ProcessRequest(rec, req, nil)
			require.NoError(t, err)
			assert.Equal(t, middleware.StatusRespond, status)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
			assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
		})
	}
}

func TestRESTAsMCPToolView_RewritesToolsListForCallerProxy(t *testing.T) {
	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec}}

	sessionID := initializeSyntheticAdapterSession(t, mw)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/list",
		"params":{}
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body, "result", "response body: %s", rec.Body.String())
	result := body["result"].(map[string]any)
	tools := result["tools"].([]any)
	require.Len(t, tools, 1)
	tool := tools[0].(map[string]any)
	assert.Equal(t, "orders", tool["name"])
	assert.Equal(t, "proxy one list", tool["description"])
}

func TestWriteSyntheticMCPToolsListResponse_FailsClosedWhenRewriteFails(t *testing.T) {
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{}}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	sdkResponse := newBufferedResponseWriter()
	sdkResponse.Header().Set("Content-Type", "application/json")
	sdkResponse.WriteHeader(http.StatusOK)
	_, err := sdkResponse.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"hidden"}]`))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	mw.writeSyntheticMCPToolsListResponse(rec, req, sdkResponse, oas.MCPToolView{
		Tools: []oas.DerivedTool{{
			Name:        "visible",
			InputSchema: map[string]any{"type": "object"},
		}},
	}, true)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "hidden")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotContains(t, body, "result")
	rpcErr := body["error"].(map[string]any)
	assert.EqualValues(t, mcp.JSONRPCInternalError, rpcErr["code"])
}

func TestBuildAdapterSpec_ReusedSDKAdapterUsesUpdatedToolViewsForCalls(t *testing.T) {
	rest := restSourceSpec("rest-1", "org-1", true)
	initialProxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Allow: boolPtr(true)},
		},
	})
	first, err := buildMCPAdapterSpec(rest, []*APISpec{initialProxy}, nil)
	require.NoError(t, err)

	updatedProxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Name: "make_order", Allow: boolPtr(true)},
		},
	})
	reused, err := buildMCPAdapterSpec(rest, []*APISpec{updatedProxy}, first)
	require.NoError(t, err)
	require.Same(t, first.MCPAdapter.SDKAdapter, reused.MCPAdapter.SDKAdapter)

	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"rest-1":     rest,
			reused.APIID: reused,
			"proxy-1":    updatedProxy,
		},
		apisHandlesByID: &sync.Map{},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/orders", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	})})
	snapshot, err := computeMCPPairing([]*APISpec{rest, updatedProxy})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(snapshot)

	tool := mustAdapterTool(t, reused, "make_order")
	rec, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, reused, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Status())
}

func TestCallMCPAdapterTool_RequiresActualCallerProxyToBeAllowed(t *testing.T) {
	gw, adapterSpec, sourceCalled := syntheticAdapterGatewayForCallTest(t)
	tool := mustAdapterTool(t, adapterSpec, "orders")

	_, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "forged-proxy"),
		&tool,
		map[string]any{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "caller proxy is not allowed")
	assert.False(t, *sourceCalled)

	rec, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.NoError(t, err)
	assert.True(t, *sourceCalled)
	assert.Equal(t, http.StatusOK, rec.Status())
}

func TestCallMCPAdapterTool_UsesExactSourceRESTAPIID(t *testing.T) {
	gw, adapterSpec, sourceCalled := syntheticAdapterGatewayForCallTest(t)
	decoyCalled := false
	gw.apisByID["rest-10"] = restSourceSpec("rest-10", "org-1", true)
	gw.apisHandlesByID.Store("rest-10", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		decoyCalled = true
		w.WriteHeader(http.StatusTeapot)
	})})

	tool := mustAdapterTool(t, adapterSpec, "orders")
	rec, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.NoError(t, err)
	assert.True(t, *sourceCalled)
	assert.False(t, decoyCalled)
	assert.Equal(t, http.StatusOK, rec.Status())
}

func TestCallMCPAdapterTool_AliasUsesCanonicalRequest(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	var gotMethod, gotPath string
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})})

	tool := mustAdapterTool(t, adapterSpec, "orders")
	_, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, "/orders", gotPath)
}

func TestCallMCPAdapterTool_RejectsToolHiddenFromCallerProxy(t *testing.T) {
	gw, adapterSpec, sourceCalled := syntheticAdapterGatewayForCallTest(t)
	tool := mustAdapterTool(t, adapterSpec, "make_order")

	_, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool not found")
	assert.False(t, *sourceCalled)
}

func TestCallMCPAdapterTool_LogsToolHiddenFromCallerProxy(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.WarnLevel)
	originalLog := log
	log = logger
	t.Cleanup(func() {
		log = originalLog
	})

	gw, adapterSpec, sourceCalled := syntheticAdapterGatewayForCallTest(t)
	tool := mustAdapterTool(t, adapterSpec, "make_order")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, &user.SessionState{KeyID: "session-key-1"})

	_, err := gw.callMCPAdapterTool(req, adapterSpec, &tool, map[string]any{})
	require.Error(t, err)
	assert.False(t, *sourceCalled)

	var warningEntry *logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && entry.Message == "MCP tool is not exposed for caller proxy" {
			warningEntry = entry
			break
		}
	}
	require.NotNil(t, warningEntry)
	assert.Equal(t, "make_order", warningEntry.Data["tool_name"])
	assert.Equal(t, "proxy-1", warningEntry.Data["proxy_api_id"])
	assert.Equal(t, "rest-1", warningEntry.Data["source_rest_api_id"])
	assert.Equal(t, adapterSpec.APIID, warningEntry.Data["adapter_api_id"])
	assert.NotContains(t, warningEntry.Data, "session_key")
}

func TestCallMCPAdapterTool_RunsSourceRESTMiddlewareChain(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	source := gw.apisByID["rest-1"]
	base := &BaseMiddleware{Spec: source, Gw: gw}
	bypass := &MCPLoopAuthBypassMiddleware{BaseMiddleware: base}
	restore := &MCPLoopAuthRestoreMiddleware{BaseMiddleware: base}

	var order []string
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err, _ := bypass.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		order = append(order, string(ctxGetRequestStatus(r)))

		if ctxGetRequestStatus(r) != StatusOkAndIgnore {
			http.Error(w, "auth was not bypassed", http.StatusUnauthorized)
			return
		}
		order = append(order, "source-auth")

		err, _ = restore.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		order = append(order, string(ctxGetRequestStatus(r)))

		r.Header.Set("X-Source-Transform", "seen")
		order = append(order, "source-transform")

		require.Equal(t, "seen", r.Header.Get("X-Source-Transform"))
		order = append(order, "upstream")
		w.WriteHeader(http.StatusOK)
	})})

	tool := mustAdapterTool(t, adapterSpec, "orders")
	rec, err := defaultMCPAdapterCallTool(
		mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"),
		&tool,
		map[string]any{},
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Status())
	assert.Equal(t, []string{
		string(StatusOkAndIgnore),
		"source-auth",
		string(StatusOk),
		"source-transform",
		"upstream",
	}, order)
}

func TestCallMCPAdapterTool_ForwardsQueryParamsThroughJSONRPC(t *testing.T) {
	rest := restSourceSpec("rest-query", "org-1", true)
	rest.OAS.Paths.Set("/orders", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "list_orders",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{Value: &openapi3.Parameter{
					Name:     "limit",
					In:       openapi3.ParameterInQuery,
					Required: true,
					Schema:   openapi3.NewStringSchema().NewRef(),
				}},
			},
		},
	})
	proxy := pairedMCPProxySpec("proxy-query", "org-1", "rest-query", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Allow: boolPtr(true)},
		},
	})
	adapterSpec, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, nil)
	require.NoError(t, err)

	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"rest-query":      rest,
			adapterSpec.APIID: adapterSpec,
			"proxy-query":     proxy,
		},
		apisHandlesByID: &sync.Map{},
	}
	gw.apisHandlesByID.Store("rest-query", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"query":"` + r.URL.RawQuery + `"}`))
		require.NoError(t, err)
	})})
	snapshot, err := computeMCPPairing([]*APISpec{rest, proxy})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(snapshot)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
	sessionID := initializeSyntheticAdapterSession(t, mw, "proxy-query")

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{
		"jsonrpc":"2.0",
		"id":2,
		"method":"tools/call",
		"params":{"name":"orders","arguments":{"limit":10}}
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-query")
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)
	require.NoError(t, err)
	require.Equal(t, middleware.StatusRespond, status)
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body, "result", "response body: %s", rec.Body.String())
	result := body["result"].(map[string]any)
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"]
	assert.Equal(t, `{"query":"limit=10"}`, text)
}

func initializeSyntheticAdapterSession(t *testing.T, mw *JSONRPCMiddleware, callerProxyID ...string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if len(callerProxyID) > 0 {
		ctxSetMCPAdapterCallerProxyID(req, callerProxyID[0])
	}
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)
	require.NoError(t, err)
	require.Equal(t, middleware.StatusRespond, status)
	require.Equal(t, http.StatusOK, rec.Code)

	sessionID := rec.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)
	return sessionID
}

func buildSyntheticAdapterForRuntimeTest(t *testing.T) *APISpec {
	t.Helper()

	rest := restSourceSpec("rest-1", "org-1", true)
	proxy1 := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders", Description: "proxy one list", Allow: boolPtr(true)},
		},
	})
	proxy2 := pairedMCPProxySpec("proxy-2", "org-1", "rest-1", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order"}, Name: "make_order", Description: "proxy two create", Allow: boolPtr(true)},
		},
	})

	adapterSpec, err := buildMCPAdapterSpec(rest, []*APISpec{proxy1, proxy2}, nil)
	require.NoError(t, err)
	return adapterSpec
}

func syntheticAdapterGatewayForCallTest(t *testing.T) (*Gateway, *APISpec, *bool) {
	t.Helper()

	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	sourceSpec := restSourceSpec("rest-1", "org-1", true)
	sourceCalled := false

	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"rest-1":          sourceSpec,
			adapterSpec.APIID: adapterSpec,
			"proxy-1":         pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil),
			"proxy-2":         pairedMCPProxySpec("proxy-2", "org-1", "rest-1", nil),
		},
		apisHandlesByID: &sync.Map{},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
		require.NoError(t, err)
	})})

	snapshot, err := computeMCPPairing([]*APISpec{
		sourceSpec,
		pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil),
		pairedMCPProxySpec("proxy-2", "org-1", "rest-1", nil),
	})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(snapshot)

	return gw, adapterSpec, &sourceCalled
}

func mcpAdapterCallContext(t *testing.T, gw *Gateway, adapterSpec *APISpec, callerProxyID string) context.Context {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPAdapterCallerProxyID(req, callerProxyID)
	installMCPAdapterCallContext(req, gw, adapterSpec)
	return req.Context()
}

func mustAdapterTool(t *testing.T, adapterSpec *APISpec, name string) oas.DerivedTool {
	t.Helper()

	for _, tool := range adapterSpec.MCPAdapter.UnionTools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("adapter tool %q not found", name)
	return oas.DerivedTool{}
}
