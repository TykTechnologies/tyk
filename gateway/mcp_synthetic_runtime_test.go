package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/ee/middleware/upstreambasicauth"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
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

	snapshot, err := computeMCPPairing([]*APISpec{restSourceSpec("rest-1", "org-1", true), caller})
	require.NoError(t, err)
	gw.mcpPairingIndex.Set(snapshot)
	req := httptest.NewRequest(http.MethodPost, "/proxy/mcp", nil)
	setSessionForTest(req, &user.SessionState{KeyID: "test-key"})
	acceptMCPOrigin(req, caller, "")
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

	err, status := processAdmittedSyntheticForTest(t, mw, rec, req)
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

func TestSyntheticAdapterProcessRequest_RunsWithExistingJSONRPCRoutingState(t *testing.T) {
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
	httpctx.SetJSONRPCRoutingState(req, &httpctx.JSONRPCRoutingState{
		Method: mcp.MethodToolsCall,
	})
	httpctx.SetJsonRPCRouting(req, true)
	rec := httptest.NewRecorder()

	err, status := processAdmittedSyntheticForTest(t, mw, rec, req)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"result"`)
}

func TestRESTAsMCPAdapter_ProtocolSpecificGETAndDELETE(t *testing.T) {
	adapterSpec := buildSyntheticAdapterForRuntimeTest(t)
	gw, _, _ := syntheticAdapterGatewayForCallTest(t)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}

	t.Run("modern methods are rejected with POST allowance", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				req := httptest.NewRequest(method, "/mcp", nil)
				req.Header.Set("Accept", "application/json, text/event-stream")
				req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
				rec := httptest.NewRecorder()

				err, status := mw.ProcessRequest(rec, req, nil)
				require.NoError(t, err)
				assert.Equal(t, middleware.StatusRespond, status)
				assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
				assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
			})
		}
	})

	sessionID := initializeSyntheticAdapterSession(t, mw)
	prepareLegacy := func(method string) *http.Request {
		req := httptest.NewRequest(method, "/mcp", nil)
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set(mcp.HeaderSessionID, sessionID)
		ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
		caller := gw.apisByID["proxy-1"]
		require.NotNil(t, caller)
		acceptMCPOrigin(req, caller, "")
		require.True(t, establishMCPAdapterOriginHop(req, gw, caller, adapterSpec))
		return req
	}

	t.Run("legacy GET opens and cancellation closes the SSE stream", func(t *testing.T) {
		req := prepareLegacy(http.MethodGet)
		ctx, cancel := context.WithCancel(req.Context())
		req = req.WithContext(ctx)
		rec := newHeaderSignalRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = mw.ProcessRequest(rec, req, nil)
		}()
		select {
		case <-rec.wroteHeader:
		case <-time.After(2 * time.Second):
			t.Fatal("legacy GET did not open an SSE response")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("legacy GET did not stop after request cancellation")
		}
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	})

	t.Run("legacy DELETE terminates the session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		err, status := mw.ProcessRequest(rec, prepareLegacy(http.MethodDelete), nil)
		require.NoError(t, err)
		require.Equal(t, middleware.StatusRespond, status)
		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	})
}

func TestRESTAsMCPProxy_GETWithoutLegacySessionIsMethodNotAllowed(t *testing.T) {
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: proxy}}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()

	err, status := mw.ProcessRequest(rec, req, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
}

type headerSignalRecorder struct {
	*httptest.ResponseRecorder
	once        sync.Once
	wroteHeader chan struct{}
}

func newHeaderSignalRecorder() *headerSignalRecorder {
	return &headerSignalRecorder{ResponseRecorder: httptest.NewRecorder(), wroteHeader: make(chan struct{})}
}

func (r *headerSignalRecorder) signal() { r.once.Do(func() { close(r.wroteHeader) }) }

func (r *headerSignalRecorder) WriteHeader(status int) {
	r.ResponseRecorder.WriteHeader(status)
	r.signal()
}

func (r *headerSignalRecorder) Write(body []byte) (int, error) {
	written, err := r.ResponseRecorder.Write(body)
	r.signal()
	return written, err
}

func (r *headerSignalRecorder) Flush() {
	r.ResponseRecorder.Flush()
	r.signal()
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

	err, status := processAdmittedSyntheticForTest(t, mw, rec, req)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, status)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Contains(t, body, "result", "response body: %s", rec.Body.String())
	result := body["result"].(map[string]any)
	assert.Equal(t, "private", result["cacheScope"])
	assert.EqualValues(t, 0, result["ttlMs"])
	tools := result["tools"].([]any)
	require.Len(t, tools, 1)
	tool := tools[0].(map[string]any)
	assert.Equal(t, "orders", tool["name"])
	assert.Equal(t, "proxy one list", tool["description"])
}

func TestRewriteMCPToolsListResponse_PreservesUnchangedBytesAndHints(t *testing.T) {
	view := oas.MCPToolView{Tools: []oas.DerivedTool{{
		Name:        "orders",
		Description: "list orders",
		InputSchema: map[string]any{"type": "object"},
	}}}
	tools, err := json.Marshal(view.Tools)
	require.NoError(t, err)
	original := []byte("{\n  \"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {\"tools\": " + string(tools) + ", \"cacheScope\": \"public\", \"ttlMs\": 5000}\n}")

	rewritten, changed, err := rewriteMCPToolsListResponse(original, view)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, original, rewritten)
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
	}, true, nil)

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

func TestCallMCPAdapterTool_PropagatesSDKOperationCancellationToSource(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	started := make(chan struct{})
	observedCause := make(chan error, 1)
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		observedCause <- context.Cause(r.Context())
		w.WriteHeader(http.StatusRequestTimeout)
	})})

	tool := mustAdapterTool(t, adapterSpec, "orders")
	operationCtx, cancel := context.WithCancelCause(mcpAdapterCallContext(t, gw, adapterSpec, "proxy-1"))
	result := make(chan error, 1)
	go func() {
		_, err := defaultMCPAdapterCallTool(operationCtx, &tool, map[string]any{})
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("source operation did not start")
	}
	cause := errors.New("cancel selected MCP call")
	cancel(cause)
	select {
	case got := <-observedCause:
		assert.ErrorIs(t, got, cause)
	case <-time.After(time.Second):
		t.Fatal("source handler did not observe cancellation")
	}
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("cancelled adapter call did not return")
	}
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
	hook := &logrustest.Hook{}
	originalLevel := log.GetLevel()
	originalHooks := log.ReplaceHooks(make(logrus.LevelHooks))
	installedHooks := cloneLogrusHooks(originalHooks)
	installedHooks.Add(hook)
	log.ReplaceHooks(installedHooks)
	log.SetLevel(logrus.WarnLevel)
	t.Cleanup(func() {
		log.SetLevel(originalLevel)
		log.ReplaceHooks(originalHooks)
	})

	gw, adapterSpec, sourceCalled := syntheticAdapterGatewayForCallTest(t)
	tool := mustAdapterTool(t, adapterSpec, "make_order")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctxSetMCPAdapterCallerProxyID(req, "proxy-1")
	setSessionForTest(req, &user.SessionState{KeyID: "session-key-1"})

	_, err := gw.callMCPAdapterTool(context.Background(), req, adapterSpec, &tool, map[string]any{})
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

func cloneLogrusHooks(hooks logrus.LevelHooks) logrus.LevelHooks {
	cloned := make(logrus.LevelHooks, len(hooks))
	for level, levelHooks := range hooks {
		cloned[level] = append([]logrus.Hook(nil), levelHooks...)
	}
	return cloned
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

	err, status := processAdmittedSyntheticForTest(t, mw, rec, req)
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

func TestCallMCPAdapterTool_DropsUnsafeSourceOASHeaderProjection(t *testing.T) {
	for _, managedAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed_auth_%t", managedAuth), func(t *testing.T) {
			rest := restSourceSpec("rest-headers", "org-1", true)
			if managedAuth {
				rest.UpstreamAuth = apidef.UpstreamAuth{
					Enabled: true,
					BasicAuth: apidef.UpstreamBasicAuth{
						Enabled:  true,
						Username: "managed-user",
						Password: "managed-password",
					},
				}
			}
			rest.OAS.Paths.Set("/headers", &openapi3.PathItem{
				Get: &openapi3.Operation{
					OperationID: "read_headers",
					Parameters: openapi3.Parameters{
						&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "Authorization", In: openapi3.ParameterInHeader, Schema: openapi3.NewStringSchema().NewRef()}},
						&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "X-Region", In: openapi3.ParameterInHeader, Schema: openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema()).NewRef()}},
					},
				},
			})
			proxy := pairedMCPProxySpec("proxy-headers", "org-1", "rest-headers", &oas.TykMCPServer{
				Primitives: []oas.TykMCPServerPrimitive{{
					Source: oas.TykMCPServerSource{OperationID: "read_headers"}, Name: "headers", Allow: boolPtr(true),
					Parameters: []oas.TykMCPServerParameter{
						{Param: "Authorization", Name: "region"},
						{Param: "X-Region", Name: "Authorization"},
					},
				}},
			})
			adapterSpec, err := buildMCPAdapterSpec(rest, []*APISpec{proxy}, nil)
			require.NoError(t, err)
			tool := mustAdapterTool(t, adapterSpec, "headers")
			require.Equal(t, "Authorization", tool.ParamSourceNames["region"])
			require.Equal(t, "X-Region", tool.ParamSourceNames["Authorization"])

			gw := &Gateway{
				apisByID:        map[string]*APISpec{"rest-headers": rest, adapterSpec.APIID: adapterSpec, "proxy-headers": proxy},
				apisHandlesByID: &sync.Map{},
			}
			called := false
			terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				assert.NotContains(t, r.Header.Values("Authorization"), "attacker-value")
				assert.Equal(t, "eu,us", r.Header.Get("X-Region"))
				if managedAuth {
					username, password, ok := r.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "managed-user", username)
					assert.Equal(t, "managed-password", password)
				} else {
					assert.Empty(t, r.Header.Get("Authorization"))
				}
				w.WriteHeader(http.StatusOK)
			})
			var sourceChain http.Handler = terminal
			if managedAuth {
				base := NewBaseMiddleware(gw, rest, nil, nil)
				authSpec := upstreambasicauth.NewAPISpec(rest.APIID, rest.Name, rest.IsOAS, rest.OAS, rest.UpstreamAuth)
				upstreamAuth := WrapMiddleware(base, upstreambasicauth.NewMiddleware(gw, base, authSpec))
				require.True(t, upstreamAuth.EnabledForSpec())
				upstreamProxy := &ReverseProxy{TykAPISpec: rest, Gw: gw}
				sourceChain = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Empty(t, r.Header.Get("Authorization"), "unsafe projection must be dropped before source auth")
					err, status := upstreamAuth.ProcessRequest(w, r, nil)
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, status)
					outbound := r.Clone(r.Context())
					upstreamProxy.addAuthInfo(outbound, r)
					terminal.ServeHTTP(w, outbound)
				})
			}
			gw.apisHandlesByID.Store("rest-headers", &ChainObject{ThisHandler: sourceChain})
			snapshot, err := computeMCPPairing([]*APISpec{rest, proxy})
			require.NoError(t, err)
			gw.mcpPairingIndex.Set(snapshot)

			rec, err := defaultMCPAdapterCallTool(
				mcpAdapterCallContext(t, gw, adapterSpec, "proxy-headers"),
				&tool,
				map[string]any{"region": "attacker-value", "Authorization": []any{"eu", "us"}},
			)
			require.NoError(t, err)
			require.True(t, called)
			require.Equal(t, http.StatusOK, rec.Status())
		})
	}
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

	err, status := processAdmittedSyntheticForTest(t, mw, rec, req)
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
	return mcpadapter.WithRequestBinding(req.Context(), req.Context(), "test-owner")
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

// Unit tests entering the synthetic boundary directly must model the verified
// public hop explicitly; production never admits caller-ID-only context.
func processAdmittedSyntheticForTest(t *testing.T, mw *JSONRPCMiddleware, w http.ResponseWriter, req *http.Request) (error, int) {
	t.Helper()
	if mw.Gw == nil {
		mw.Gw, _, _ = syntheticAdapterGatewayForCallTest(t)
	}
	callerID := ctxGetMCPAdapterCallerProxyID(req)
	if callerID == "" {
		callerID = "proxy-1"
	}
	caller := mw.Gw.apisByID[callerID]
	require.NotNil(t, caller)
	callerCopy := *caller
	def := *caller.APIDefinition
	callerCopy.APIDefinition = &def
	// Policy fixtures own their session rules. Model one stable keyless public
	// principal here; dedicated identity tests exercise authenticated ownership.
	callerCopy.UseKeylessAccess = true
	acceptMCPOrigin(req, &callerCopy, "")
	require.True(t, establishMCPAdapterOriginHop(req, mw.Gw, &callerCopy, mw.Spec))
	return mw.ProcessRequest(w, req, nil)
}
