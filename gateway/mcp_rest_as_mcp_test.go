package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/drl"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	tykctx "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/user"
)

// The pure adapter primitives (envelope marshalling, argument
// expansion, response wrapping) are unit-tested directly in
// internal/mcp/adapter. The tests in this file exercise the
// gateway-side chain shims and the MCPLoopAuthBypass middleware —
// against fakes for the pairing index — so no live Gateway instance is
// required.

func buildTestAdapterSpec() *APISpec {
	def := &apidef.APIDefinition{
		APIID: oas.AdapterAPIID("rest-1"),
		Name:  "test [MCP adapter]",
		OrgID: "org-1",
	}
	def.MarkAsMCP()
	def.Internal = true

	return &APISpec{
		APIDefinition:         def,
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		DerivedTools: []oas.DerivedTool{
			{
				Name:           "getOrder",
				Description:    "fetch an order by id",
				Method:         http.MethodGet,
				PathTemplate:   "/orders/{id}",
				ParamLocations: map[string]string{"id": "path"},
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"id"},
				},
			},
		},
	}
}

func buildRESTSpecForSDKAdapterTest(description string) *APISpec {
	def := &apidef.APIDefinition{
		APIID: "rest-1",
		Name:  "orders",
		OrgID: "org-1",
		IsOAS: true,
	}

	return &APISpec{
		APIDefinition: def,
		OAS: oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "orders", Version: "1.0.0"},
				Paths: openapi3.NewPaths(openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
					Get: &openapi3.Operation{
						OperationID: "get_order",
						Summary:     description,
						Parameters: openapi3.Parameters{
							&openapi3.ParameterRef{Value: &openapi3.Parameter{
								Name:     "id",
								In:       openapi3.ParameterInPath,
								Required: true,
								Schema:   &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							}},
						},
					},
				})),
			},
		},
	}
}

func connectGatewaySDKServer(t *testing.T, server *mcpsdk.Server, opts *mcpsdk.ClientOptions) *mcpsdk.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, serverSession.Close()) })

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "gateway-test-client", Version: "v0.0.1"}, opts)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, clientSession.Close()) })

	return clientSession
}

func assertNoGatewayToolListChanged(t *testing.T, changed <-chan struct{}) {
	t.Helper()

	select {
	case <-changed:
		t.Fatal("unexpected tools/list_changed notification")
	case <-time.After(100 * time.Millisecond):
	}
}

type testMCPPairing struct {
	proxies map[string]map[string]struct{}
	adapter map[string]string
}

func newTestMCPPairing(restID, proxyID, adapterID string) testMCPPairing {
	return testMCPPairing{
		proxies: map[string]map[string]struct{}{restID: {proxyID: {}}},
		adapter: map[string]string{restID: adapterID},
	}
}

func (p testMCPPairing) ProxyAllowedForREST(restAPIID, proxyAPIID string) bool {
	proxies, ok := p.proxies[restAPIID]
	if !ok {
		return false
	}
	_, ok = proxies[proxyAPIID]
	return ok
}

func (p testMCPPairing) AdapterForREST(restAPIID string) (string, bool) {
	v, ok := p.adapter[restAPIID]
	return v, ok
}

func TestSyntheticAdapterProcessRequest_UsesSDKAdapter(t *testing.T) {
	t.Parallel()

	spec := buildTestAdapterSpec()
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(_ context.Context, _ *oas.DerivedTool, _ map[string]any) (*mcpadapter.Recorder, error) {
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`))
	r.Header.Set("Content-Type", "application/json")

	err, code := m.ProcessRequest(w, r, nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)

	var env map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	result := env["result"].(map[string]any)
	tools := result["capabilities"].(map[string]any)["tools"].(map[string]any)
	assert.NotContains(t, tools, "listChanged")
}

func TestSyntheticAdapterProcessRequest_RoutesStreamableMethodsToSDKAdapter(t *testing.T) {
	t.Parallel()

	spec := buildTestAdapterSpec()
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(_ context.Context, _ *oas.DerivedTool, _ map[string]any) (*mcpadapter.Recorder, error) {
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/mcp/", nil)

			err, code := m.ProcessRequest(w, r, nil)
			require.NoError(t, err)
			assert.Equal(t, middleware.StatusRespond, code)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestBuildAdapterSpec_ReusesSDKAdapterAndUpdatesTools(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.config.Store(config.Config{})
	rest := buildRESTSpecForSDKAdapterTest("fetch an order")

	adapter1, err := gw.buildAdapterSpec(rest)
	require.NoError(t, err)
	require.NotNil(t, adapter1.MCPSDKAdapter)

	changed := make(chan struct{}, 1)
	session := connectGatewaySDKServer(t, adapter1.MCPSDKAdapter.Server(), &mcpsdk.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcpsdk.ToolListChangedRequest) {
			changed <- struct{}{}
		},
	})

	gw.apisMu.Lock()
	gw.apisByID = map[string]*APISpec{adapter1.APIID: adapter1}
	gw.apisMu.Unlock()

	restUpdated := buildRESTSpecForSDKAdapterTest("fetch an order by id")
	adapter2, err := gw.buildAdapterSpec(restUpdated)
	require.NoError(t, err)
	require.Same(t, adapter1.MCPSDKAdapter, adapter2.MCPSDKAdapter)
	assertNoGatewayToolListChanged(t, changed)

	list, err := session.ListTools(context.Background(), &mcpsdk.ListToolsParams{})
	require.NoError(t, err)
	require.Len(t, list.Tools, 1)
	assert.Equal(t, "get_order", list.Tools[0].Name)
	assert.Equal(t, "fetch an order by id", list.Tools[0].Description)
}

func TestBuildAdapterSpec_ReusedSDKAdapterUsesUpdatedToolViewsForCalls(t *testing.T) {
	t.Parallel()

	rest := buildRESTSpecForMCPToolViewTest()
	adapterID := oas.AdapterAPIID(rest.APIID)
	idx := pairing.New()
	idx.Set(
		map[string]string{rest.APIID: adapterID},
		map[string]map[string]struct{}{rest.APIID: {"proxy-a": {}}},
	)

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.config.Store(config.Config{})
	gw.apisByID = map[string]*APISpec{
		rest.APIID: rest,
	}
	gw.apisHandlesByID.Store(rest.APIID, &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/orders", r.URL.Path)
			assert.Equal(t, "C-123", r.URL.Query().Get("customer_id"))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write([]byte(`{"created":true}`))
			require.NoError(t, err)
		}),
	})

	initialProxy := buildMCPProxySpecForToolViewTest("proxy-a", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Allow: boolPtr(true)},
		},
	})
	adapter1, err := gw.buildAdapterSpecForProxies(rest, map[string]*APISpec{
		rest.APIID:         rest,
		initialProxy.APIID: initialProxy,
	})
	require.NoError(t, err)
	gw.apisByID[adapter1.APIID] = adapter1

	updatedProxy := buildMCPProxySpecForToolViewTest("proxy-a", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order_source"}, Name: "create_order", Allow: boolPtr(true)},
		},
	})
	adapter2, err := gw.buildAdapterSpecForProxies(rest, map[string]*APISpec{
		rest.APIID:         rest,
		updatedProxy.APIID: updatedProxy,
	})
	require.NoError(t, err)
	require.Same(t, adapter1.MCPSDKAdapter, adapter2.MCPSDKAdapter)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapter2, Gw: gw}}
	serve := func(body string, sessionID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		httpctx.SetMCPProxyCallerAPIID(r, "proxy-a")

		w := httptest.NewRecorder()
		err, code := mw.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		assert.Equal(t, middleware.StatusRespond, code)
		return w
	}

	init := serve(`{
		"jsonrpc":"2.0",
		"id":0,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"gateway-reload-test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`, "")
	require.Equal(t, http.StatusOK, init.Code)

	call := serve(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"tools/call",
		"params":{"name":"create_order","arguments":{"customer_id":"C-123"}}
	}`, init.Header().Get("Mcp-Session-Id"))

	require.Equal(t, http.StatusOK, call.Code)
	assert.Contains(t, call.Body.String(), `{\"created\":true}`)
}

// loopAuthBypassTestCase covers MCPLoopAuthBypass's three branches
// using a pairing.Static fake instead of the full Gateway plumbing.
type loopAuthBypassTestCase struct {
	name       string
	pairing    pairing.Lookup
	stampTrust *httpctx.MCPLoopTrust
	wantCode   int
	wantError  bool
	wantSess   bool
}

func TestMCPLoopAuthBypass_Branches(t *testing.T) {
	t.Parallel()

	cases := []loopAuthBypassTestCase{
		{
			name:     "no-flag-passes-through",
			pairing:  pairing.Static{"rest-1": {"proxy-1": {}}},
			wantCode: http.StatusOK,
		},
		{
			name:    "matched-flag-installs-session",
			pairing: newTestMCPPairing("rest-1", "proxy-1", oas.AdapterAPIID("rest-1")),
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-1",
				RESTAPIID:    "rest-1",
				AdapterAPIID: oas.AdapterAPIID("rest-1"),
			},
			wantCode: http.StatusOK,
			wantSess: true,
		},
		{
			name:    "rest-api-id-mismatch-returns-403",
			pairing: newTestMCPPairing("rest-1", "proxy-1", oas.AdapterAPIID("rest-1")),
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-1",
				RESTAPIID:    "rest-2",
				AdapterAPIID: oas.AdapterAPIID("rest-1"),
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name:    "adapter-api-id-mismatch-returns-403",
			pairing: newTestMCPPairing("rest-1", "proxy-1", oas.AdapterAPIID("rest-1")),
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-1",
				RESTAPIID:    "rest-1",
				AdapterAPIID: oas.AdapterAPIID("rest-2"),
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name:    "mismatched-flag-returns-403",
			pairing: newTestMCPPairing("rest-1", "proxy-real", oas.AdapterAPIID("rest-1")),
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-forged",
				RESTAPIID:    "rest-1",
				AdapterAPIID: oas.AdapterAPIID("rest-1"),
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name:    "no-pairing-record-returns-403",
			pairing: pairing.Static{},
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-1",
				RESTAPIID:    "rest-1",
				AdapterAPIID: oas.AdapterAPIID("rest-1"),
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1"}}

			mw := &MCPLoopAuthBypass{
				BaseMiddleware: &BaseMiddleware{Spec: spec},
				Pairing:        tc.pairing,
			}

			r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
			if tc.stampTrust != nil {
				httpctx.SetMCPLoopFromPairedProxy(r, tc.stampTrust)
			}

			w := httptest.NewRecorder()
			err, code := mw.ProcessRequest(w, r, nil)

			assert.Equal(t, tc.wantCode, code)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tc.wantSess {
				sess := ctxGetSession(r)
				require.NotNil(t, sess, "matched flag must install a session")
				assert.Equal(t, "mcp-loop:"+tc.stampTrust.ProxyAPIID, sess.KeyID)
			}
		})
	}
}

func TestMCPLoopAuthBypass_PreAuthorizesThenRestoreClearsBypassStatus(t *testing.T) {
	t.Parallel()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1"}}

	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	httpctx.SetMCPLoopFromPairedProxy(r, &httpctx.MCPLoopTrust{
		ProxyAPIID:   "proxy-1",
		RESTAPIID:    "rest-1",
		AdapterAPIID: oas.AdapterAPIID("rest-1"),
	})

	bypass := &MCPLoopAuthBypass{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
		Pairing:        newTestMCPPairing("rest-1", "proxy-1", oas.AdapterAPIID("rest-1")),
	}
	w := httptest.NewRecorder()
	err, code := bypass.ProcessRequest(w, r, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, httpctx.IsMCPLoopPreAuthorized(r))
	assert.Equal(t, StatusOkAndIgnore, ctxGetRequestStatus(r))

	restore := &MCPLoopAuthRestore{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	err, code = restore.ProcessRequest(w, r, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, StatusOk, ctxGetRequestStatus(r))
}

func TestMCPLoopAuthBypass_EnabledForSpec(t *testing.T) {
	t.Parallel()
	plainREST := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest"}}
	mcpProxy := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "mcp"}}
	mcpProxy.MarkAsMCP()
	adapter := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: oas.AdapterAPIID("rest")},
		IsSyntheticMCPAdapter: true,
	}

	assert.True(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: plainREST}}).EnabledForSpec())
	assert.False(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: mcpProxy}}).EnabledForSpec())
	assert.False(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: adapter}}).EnabledForSpec())
}

// TestComputeMCPPairing covers the pure pairing-rebuild logic without
// any Gateway plumbing — it operates on the same APISpec map structure
// the loader holds, but otherwise has no dependencies.
func TestComputeMCPPairing(t *testing.T) {
	t.Parallel()

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}}

	adapter := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: oas.AdapterAPIID("rest-1"), OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
	}

	proxy := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}}
	proxy.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	specs := map[string]*APISpec{
		rest.APIID:    rest,
		adapter.APIID: adapter,
		proxy.APIID:   proxy,
	}

	allowed, adapterMap := computeMCPPairing(specs)
	assert.Contains(t, allowed["rest-1"], "proxy-1")
	assert.Equal(t, oas.AdapterAPIID("rest-1"), adapterMap["rest-1"])
}

func TestComputeMCPPairing_CrossOrgRefused(t *testing.T) {
	t.Parallel()

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-A"}}
	adapter := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: oas.AdapterAPIID("rest-1"), OrgID: "org-A"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
	}
	proxy := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-B"}}
	proxy.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	specs := map[string]*APISpec{
		rest.APIID:    rest,
		adapter.APIID: adapter,
		proxy.APIID:   proxy,
	}

	allowed, _ := computeMCPPairing(specs)
	_, paired := allowed["rest-1"]
	assert.False(t, paired, "cross-org pairing must be refused")
}

func TestReferencedMCPAdapterRESTIDs_AreProxyDriven(t *testing.T) {
	t.Parallel()

	referencedREST := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}}
	unreferencedREST := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-2", OrgID: "org-1"}}

	proxy := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}}
	proxy.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	crossOrgProxy := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-cross", OrgID: "org-2"}}
	crossOrgProxy.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	specs := map[string]*APISpec{
		referencedREST.APIID:   referencedREST,
		unreferencedREST.APIID: unreferencedREST,
		proxy.APIID:            proxy,
		crossOrgProxy.APIID:    crossOrgProxy,
	}

	assert.Equal(t, []string{"rest-1"}, referencedMCPAdapterRESTIDs(specs))
}

func TestReferencedMCPAdapterRESTIDs_RemainsAfterOneProxyRemoved(t *testing.T) {
	t.Parallel()

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}}
	proxy2 := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-2", OrgID: "org-1"}}
	proxy2.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	specsAfterReload := map[string]*APISpec{
		rest.APIID:   rest,
		proxy2.APIID: proxy2,
	}

	assert.Equal(t, []string{"rest-1"}, referencedMCPAdapterRESTIDs(specsAfterReload))
}

func TestComputeMCPPairing_DuplicateProxyTargetsAllowed(t *testing.T) {
	t.Parallel()

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}}
	adapter := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: oas.AdapterAPIID("rest-1"), OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
	}
	proxy1 := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}}
	proxy1.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	proxy2 := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "proxy-2", OrgID: "org-1"}}
	proxy2.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")

	specs := map[string]*APISpec{
		rest.APIID:    rest,
		adapter.APIID: adapter,
		proxy1.APIID:  proxy1,
		proxy2.APIID:  proxy2,
	}

	allowed, adapterMap := computeMCPPairing(specs)
	require.Contains(t, allowed, "rest-1")
	assert.Contains(t, allowed["rest-1"], "proxy-1")
	assert.Contains(t, allowed["rest-1"], "proxy-2")
	assert.Equal(t, oas.AdapterAPIID("rest-1"), adapterMap["rest-1"])
}

func TestCallMCPAdapterTool_RequiresActualCallerProxyToBeAllowed(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-real": {}, "proxy-other": {}}},
	)

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})

	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
	}
	tool := &oas.DerivedTool{
		Name:           "getOrder",
		Method:         http.MethodGet,
		PathTemplate:   "/orders/{id}",
		ParamLocations: map[string]string{"id": "path"},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-forged")
	_, err := gw.callMCPAdapterTool(ctx, spec, tool, map[string]any{"id": "42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not admitted")

	ctx = httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-other")
	_, err = gw.callMCPAdapterTool(ctx, spec, tool, map[string]any{"id": "42"})
	require.NoError(t, err)
}

func TestCallMCPAdapterTool_UsesExactSourceRESTAPIID(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-source")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-source": adapterID},
		map[string]map[string]struct{}{"rest-source": {"proxy-1": {}}},
	)

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"shadow": {APIDefinition: &apidef.APIDefinition{
			APIID: "shadow",
			Name:  "rest-source",
			OrgID: "org-1",
		}},
	}
	gw.apisHandlesByID.Store("shadow", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
	})

	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-source",
	}
	tool := &oas.DerivedTool{
		Name:           "listOrders",
		Method:         http.MethodGet,
		PathTemplate:   "/orders",
		ParamLocations: map[string]string{},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-1")
	_, err := gw.callMCPAdapterTool(ctx, spec, tool, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "paired REST API handler not found")
}

func TestCallMCPAdapterTool_RunsSourceRESTMiddlewareChain(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-1": {}}},
	)

	var order []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "upstream")
		assert.Equal(t, "/orders/42", r.URL.Path)
		assert.Equal(t, "transformed", r.Header.Get("X-Request-Transform"))
		assert.Equal(t, "plugin", r.Header.Get("X-Plugin"))
		assert.Equal(t, "per-tool", r.Header.Get("X-Per-Tool"))
		w.Header().Set("X-Upstream", "seen")
		w.WriteHeader(http.StatusCreated)
	})
	requestTransform := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "request-transform")
			r.Header.Set("X-Request-Transform", "transformed")
			next.ServeHTTP(w, r)
		})
	}
	plugin := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "plugin")
			r.Header.Set("X-Plugin", "plugin")
			next.ServeHTTP(w, r)
		})
	}
	perTool := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "per-tool")
			r.Header.Set("X-Per-Tool", "per-tool")
			next.ServeHTTP(w, r)
		})
	}

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: requestTransform(plugin(perTool(upstream))),
	})

	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
	}
	tool := &oas.DerivedTool{
		Name:           "getOrder",
		Method:         http.MethodGet,
		PathTemplate:   "/orders/{id}",
		ParamLocations: map[string]string{"id": "path"},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-1")
	rec, err := gw.callMCPAdapterTool(ctx, spec, tool, map[string]any{"id": "42"})

	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, rec.Status())
	assert.Equal(t, "seen", rec.Header().Get("X-Upstream"))
	assert.Equal(t, []string{"request-transform", "plugin", "per-tool", "upstream"}, order)
}

func TestHandleDeleteAPI_RefusesRESTSourceWithPairedMCPProxy(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.config.Store(config.Config{AppPath: t.TempDir()})

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1", IsOAS: true}}
	proxyDef := &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}
	proxyDef.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	proxy := &APISpec{APIDefinition: proxyDef}
	proxy2Def := &apidef.APIDefinition{APIID: "proxy-2", OrgID: "org-1"}
	proxy2Def.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	proxy2 := &APISpec{APIDefinition: proxy2Def}

	gw.apisByID = map[string]*APISpec{
		rest.APIID:   rest,
		proxy.APIID:  proxy,
		proxy2.APIID: proxy2,
	}

	obj, code := gw.handleDeleteAPI("rest-1")

	assert.Equal(t, http.StatusConflict, code)
	assert.Contains(t, obj.(apiStatusMessage).Message, "proxy-1")
	assert.Contains(t, obj.(apiStatusMessage).Message, "proxy-2")
}

func TestCallMCPAdapterTool_ForwardsQueryParamsThroughJSONRPC(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-1": {}}},
	)

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/orders", r.URL.Path)
			assert.Equal(t, "open", r.URL.Query().Get("status"))
			assert.Equal(t, "25", r.URL.Query().Get("limit"))
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"ok":true}`))
			require.NoError(t, err)
		}),
	})

	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, Name: "orders [MCP adapter]", OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		DerivedTools: []oas.DerivedTool{
			{
				Name:           "list_orders",
				Method:         http.MethodGet,
				PathTemplate:   "/orders",
				ParamLocations: map[string]string{"status": "query", "limit": "query"},
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"status": map[string]any{"type": "string"},
						"limit":  map[string]any{"type": "integer"},
					},
				},
			},
		},
	}
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
			return gw.callMCPAdapterTool(ctx, spec, tool, args)
		},
	})
	require.NoError(t, err)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	serve := func(body string, sessionID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		httpctx.SetMCPProxyCallerAPIID(r, "proxy-1")

		w := httptest.NewRecorder()
		err, code := mw.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		assert.Equal(t, middleware.StatusRespond, code)
		return w
	}

	init := serve(`{
		"jsonrpc":"2.0",
		"id":0,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"gateway-query-test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`, "")
	require.Equal(t, http.StatusOK, init.Code)
	sessionID := init.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)

	w := serve(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"tools/call",
		"params":{"name":"list_orders","arguments":{"status":"open","limit":25}}
	}`, sessionID)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `{\"ok\":true}`)
}

func TestRESTAsMCPToolCall_RejectsUnknownArgumentsBeforeSourceChain(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-1": {}}},
	)

	called := false
	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
	})

	spec := buildTestAdapterSpec()
	spec.SourceRESTAPIID = "rest-1"
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(ctx context.Context, tool *oas.DerivedTool, args map[string]any) (*mcpadapter.Recorder, error) {
			return gw.callMCPAdapterTool(ctx, spec, tool, args)
		},
	})
	require.NoError(t, err)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	serve := func(body string, sessionID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		httpctx.SetMCPProxyCallerAPIID(r, "proxy-1")

		w := httptest.NewRecorder()
		err, code := mw.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		assert.Equal(t, middleware.StatusRespond, code)
		return w
	}

	init := serve(`{
		"jsonrpc":"2.0",
		"id":0,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"gateway-unknown-args-test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`, "")
	require.Equal(t, http.StatusOK, init.Code)
	sessionID := init.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)

	w := serve(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"tools/call",
		"params":{"name":"getOrder","arguments":{"id":"42","unknown":"x"}}
	}`, sessionID)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"code":-32602`)
	assert.Contains(t, w.Body.String(), `unknown argument`)
	assert.False(t, called)
}

func TestRESTAsMCPAdapter_RejectsNonPOSTMethods(t *testing.T) {
	t.Parallel()

	spec := buildTestAdapterSpec()
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(context.Context, *oas.DerivedTool, map[string]any) (*mcpadapter.Recorder, error) {
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/mcp/", nil)
	w := httptest.NewRecorder()
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: &Gateway{}}}

	err, code := mw.ProcessRequest(w, r, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Equal(t, http.MethodPost, w.Header().Get("Allow"))
}

func TestDeriveMCPAdapterCatalogue_BuildsProxySpecificToolViewsAndUnion(t *testing.T) {
	t.Parallel()

	rest := buildRESTSpecForMCPToolViewTest()
	proxyA := buildMCPProxySpecForToolViewTest("proxy-a", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{
				Source:      oas.TykMCPServerSource{OperationID: "create_order_source"},
				Name:        "create_order",
				Allow:       boolPtr(true),
				Description: "Place a new order",
				Parameters: []oas.TykMCPServerParameter{
					{Param: "customer_id", Description: "Customer placing the order"},
				},
			},
		},
	})
	proxyB := buildMCPProxySpecForToolViewTest("proxy-b", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Allow: boolPtr(true)},
		},
	})

	catalogue, err := deriveMCPAdapterCatalogueForProxies(rest, map[string]*APISpec{
		rest.APIID:   rest,
		proxyA.APIID: proxyA,
		proxyB.APIID: proxyB,
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"create_order", "list_orders"}, derivedToolNames(catalogue.tools))
	require.Contains(t, catalogue.proxyToolViews, "proxy-a")
	assert.Equal(t, []string{"create_order"}, catalogue.proxyToolViews["proxy-a"].ToolNames())
	require.Contains(t, catalogue.proxyToolViews, "proxy-b")
	assert.Equal(t, []string{"list_orders"}, catalogue.proxyToolViews["proxy-b"].ToolNames())

	createTool, ok := catalogue.proxyToolViews["proxy-a"].ToolByName("create_order")
	require.True(t, ok)
	assert.Equal(t, "create_order_source", createTool.OperationID)
	assert.Equal(t, "create_order_source", createTool.CanonicalName)
	props := createTool.InputSchema["properties"].(map[string]any)
	customerID := props["customer_id"].(map[string]any)
	assert.Equal(t, "Customer placing the order", customerID["description"])
}

func TestRESTAsMCPToolView_RewritesToolsListForCallerProxy(t *testing.T) {
	t.Parallel()

	spec := buildTestAdapterSpec()
	spec.DerivedTools = []oas.DerivedTool{
		{
			OperationID:    "createOrder",
			CanonicalName:  "createOrder",
			Name:           "createOrder",
			Description:    "source create order",
			Method:         http.MethodPost,
			PathTemplate:   "/orders",
			ParamLocations: map[string]string{"customer_id": "query"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"customer_id": map[string]any{"type": "string"}}},
		},
		{
			OperationID:    "listOrders",
			CanonicalName:  "listOrders",
			Name:           "listOrders",
			Description:    "source list orders",
			Method:         http.MethodGet,
			PathTemplate:   "/orders",
			ParamLocations: map[string]string{"status": "query"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"status": map[string]any{"type": "string"}}},
		},
		{
			OperationID:    "createOrder",
			CanonicalName:  "createOrder",
			Name:           "create_order",
			Description:    "Place a new order",
			Method:         http.MethodPost,
			PathTemplate:   "/orders",
			ParamLocations: map[string]string{"customer_id": "query"},
			InputSchema:    map[string]any{"type": "object", "properties": map[string]any{"customer_id": map[string]any{"type": "string", "description": "Customer placing the order"}}},
		},
	}
	spec.MCPProxyToolViews = map[string]oas.MCPToolView{
		"proxy-a": {
			Tools: []oas.DerivedTool{
				spec.DerivedTools[2],
			},
		},
		"proxy-b": {
			Tools: []oas.DerivedTool{
				spec.DerivedTools[1],
			},
		},
	}

	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(_ context.Context, _ *oas.DerivedTool, _ map[string]any) (*mcpadapter.Recorder, error) {
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: &Gateway{}}}
	serve := func(body string, sessionID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		httpctx.SetMCPProxyCallerAPIID(r, "proxy-a")

		w := httptest.NewRecorder()
		err, code := mw.ProcessRequest(w, r, nil)
		require.NoError(t, err)
		assert.Equal(t, middleware.StatusRespond, code)
		return w
	}

	init := serve(`{
		"jsonrpc":"2.0",
		"id":0,
		"method":"initialize",
		"params":{
			"protocolVersion":"2025-06-18",
			"clientInfo":{"name":"gateway-list-test","version":"v0.0.1"},
			"capabilities":{}
		}
	}`, "")
	require.Equal(t, http.StatusOK, init.Code)

	list := serve(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, init.Header().Get("Mcp-Session-Id"))
	require.Equal(t, http.StatusOK, list.Code)

	var env map[string]any
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &env))
	tools := env["result"].(map[string]any)["tools"].([]any)
	require.Len(t, tools, 1)
	tool := tools[0].(map[string]any)
	assert.Equal(t, "create_order", tool["name"])
	assert.Equal(t, "Place a new order", tool["description"])
	assert.NotContains(t, list.Body.String(), "listOrders")
	props := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
	customerID := props["customer_id"].(map[string]any)
	assert.Equal(t, "Customer placing the order", customerID["description"])
}

func TestCallMCPAdapterTool_AliasUsesCanonicalRequest(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-a": {}}},
	)

	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/orders/42", r.URL.Path)
			assert.Equal(t, "open", r.URL.Query().Get("status"))
			w.WriteHeader(http.StatusAccepted)
		}),
	})

	aliasTool := oas.DerivedTool{
		OperationID:    "getOrder",
		CanonicalName:  "getOrder",
		Name:           "find_order",
		Method:         http.MethodGet,
		PathTemplate:   "/orders/{id}",
		ParamLocations: map[string]string{"id": "path", "status": "query"},
		InputSchema:    map[string]any{"type": "object"},
	}
	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		MCPProxyToolViews: map[string]oas.MCPToolView{
			"proxy-a": {Tools: []oas.DerivedTool{aliasTool}},
		},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-a")
	rec, err := gw.callMCPAdapterTool(ctx, spec, &aliasTool, map[string]any{"id": "42", "status": "open"})

	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, http.StatusAccepted, rec.Status())
}

func TestCallMCPAdapterTool_RejectsToolHiddenFromCallerProxy(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-a": {}}},
	)

	called := false
	gw := &Gateway{mcpPairing: idx, apisHandlesByID: new(sync.Map)}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}},
	}
	gw.apisHandlesByID.Store("rest-1", &ChainObject{
		ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
	})

	visible := oas.DerivedTool{
		OperationID:    "listOrders",
		CanonicalName:  "listOrders",
		Name:           "listOrders",
		Method:         http.MethodGet,
		PathTemplate:   "/orders",
		ParamLocations: map[string]string{},
	}
	hidden := oas.DerivedTool{
		OperationID:    "getOrder",
		CanonicalName:  "getOrder",
		Name:           "getOrder",
		Method:         http.MethodGet,
		PathTemplate:   "/orders/{id}",
		ParamLocations: map[string]string{"id": "path"},
	}
	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		MCPProxyToolViews: map[string]oas.MCPToolView{
			"proxy-a": {Tools: []oas.DerivedTool{visible}},
		},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-a")
	_, err := gw.callMCPAdapterTool(ctx, spec, &hidden, map[string]any{"id": "42"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not exposed")
	assert.False(t, called)
}

func TestCallMCPAdapterTool_LogsToolHiddenFromCallerProxy(t *testing.T) {
	logger, hook := logrustest.NewNullLogger()
	previousMainLog := mainLog
	mainLog = logger.WithField("prefix", "test")
	t.Cleanup(func() { mainLog = previousMainLog })

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(
		map[string]string{"rest-1": adapterID},
		map[string]map[string]struct{}{"rest-1": {"proxy-a": {}}},
	)

	gw := &Gateway{mcpPairing: idx}
	visible := oas.DerivedTool{
		OperationID:    "listOrders",
		CanonicalName:  "listOrders",
		Name:           "listOrders",
		Method:         http.MethodGet,
		PathTemplate:   "/orders",
		ParamLocations: map[string]string{},
	}
	hidden := oas.DerivedTool{
		OperationID:    "getOrder",
		CanonicalName:  "getOrder",
		Name:           "getOrder",
		Method:         http.MethodGet,
		PathTemplate:   "/orders/{id}",
		ParamLocations: map[string]string{"id": "path"},
	}
	spec := &APISpec{
		APIDefinition:         &apidef.APIDefinition{APIID: adapterID, OrgID: "org-1"},
		IsSyntheticMCPAdapter: true,
		SourceRESTAPIID:       "rest-1",
		MCPProxyToolViews: map[string]oas.MCPToolView{
			"proxy-a": {Tools: []oas.DerivedTool{visible}},
		},
	}

	ctx := httpctx.ContextWithMCPProxyCallerAPIID(context.Background(), "proxy-a")
	ctx = context.WithValue(ctx, tykctx.SessionData, &user.SessionState{KeyID: "agent-key-1"})
	_, err := gw.callMCPAdapterTool(ctx, spec, &hidden, map[string]any{"id": "42"})

	require.Error(t, err)
	require.Len(t, hook.Entries, 1)
	entry := hook.LastEntry()
	assert.Equal(t, logrus.WarnLevel, entry.Level)
	assert.Contains(t, entry.Message, "MCP tool is not exposed")
	assert.Equal(t, "getOrder", entry.Data["tool_name"])
	assert.Equal(t, "proxy-a", entry.Data["proxy_api_id"])
	assert.Equal(t, "rest-1", entry.Data["source_rest_api_id"])
	assert.Equal(t, adapterID, entry.Data["adapter_api_id"])
	assert.Equal(t, "agent-key-1", entry.Data["session_key"])
}

func TestValidatePairedMCPAdapterUpstream_RejectsAliasConflictAcrossSameOrgProxies(t *testing.T) {
	t.Parallel()

	rest := buildRESTSpecForMCPToolViewTest()
	existing := buildMCPProxySpecForToolViewTest("proxy-existing", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "list_orders"}, Name: "orders"},
		},
	})
	incoming := buildMCPProxyOASForToolViewTest("proxy-incoming", "org-1", rest.APIID, &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order_source"}, Name: "orders"},
		},
	})
	gw := &Gateway{}
	gw.apisByID = map[string]*APISpec{
		rest.APIID:     rest,
		existing.APIID: existing,
	}

	errMsg, code := gw.validatePairedMCPAdapterUpstream(httptest.NewRequest(http.MethodPost, "/tyk/mcps", nil), incoming)

	require.NotEmpty(t, errMsg)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, errMsg, "alias conflict")
	assert.Contains(t, errMsg, "orders")
}

func TestAPISpecValidate_AllowsMCPServerExtensionOnPairedProxy(t *testing.T) {
	t.Parallel()

	doc := buildMCPProxyOASForToolViewTest("proxy-a", "org-1", "rest-views", &oas.TykMCPServer{
		Primitives: []oas.TykMCPServerPrimitive{
			{Source: oas.TykMCPServerSource{OperationID: "create_order_source"}, Allow: boolPtr(true)},
		},
	})

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "proxy-a",
			Name:  "proxy-a",
			OrgID: "org-1",
			IsOAS: true,
			Proxy: apidef.ProxyConfig{
				TargetURL: oas.AdapterLoopURL("rest-views"),
			},
		},
		OAS: *doc,
	}

	require.NoError(t, spec.Validate(config.OASConfig{}))
}

func TestHandleDeleteMCP_DeletesPairedProxyPersistedWithOASSuffix(t *testing.T) {
	t.Parallel()

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/apps", 0755))
	require.NoError(t, afero.WriteFile(fs, "/apps/proxy-1.json", []byte(`{}`), 0644))
	require.NoError(t, afero.WriteFile(fs, "/apps/proxy-1-oas.json", []byte(`{}`), 0644))

	gw := &Gateway{}
	gw.config.Store(config.Config{AppPath: "/apps"})

	proxyDef := &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}
	proxyDef.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	gw.apisByID = map[string]*APISpec{
		proxyDef.APIID: {APIDefinition: proxyDef},
	}

	_, code := gw.handleDeleteMCP("proxy-1", fs)

	assert.Equal(t, http.StatusOK, code)
	_, err := fs.Stat("/apps/proxy-1.json")
	assert.Error(t, err)
	_, err = fs.Stat("/apps/proxy-1-oas.json")
	assert.Error(t, err)
}

func TestAlignPairedMCPProxyGatewayTags_CopiesSourceRESTTags(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.apisByID = map[string]*APISpec{
		"rest-1": {APIDefinition: &apidef.APIDefinition{
			APIID:        "rest-1",
			OrgID:        "org-1",
			TagsDisabled: false,
			Tags:         []string{"edge-a", "edge-b"},
		}},
	}

	proxyDef := &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}
	proxyDef.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	oasObj := &oas.OAS{}
	oasObj.SetTykExtension(&oas.XTykAPIGateway{})

	require.NoError(t, gw.alignPairedMCPProxyGatewayTags(proxyDef, oasObj))

	assert.False(t, proxyDef.TagsDisabled)
	assert.Equal(t, []string{"edge-a", "edge-b"}, proxyDef.Tags)
	require.NotNil(t, oasObj.GetTykExtension().Server.GatewayTags)
	assert.True(t, oasObj.GetTykExtension().Server.GatewayTags.Enabled)
	assert.Equal(t, []string{"edge-a", "edge-b"}, oasObj.GetTykExtension().Server.GatewayTags.Tags)
}

func TestRESTAsMCPPolicy_DeniesBlockedToolBeforeSDK(t *testing.T) {
	t.Parallel()

	spec := buildTestAdapterSpec()
	called := false
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(_ context.Context, _ *oas.DerivedTool, _ map[string]any) (*mcpadapter.Recorder, error) {
			called = true
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	gw := &Gateway{}
	gw.apisByID = map[string]*APISpec{
		"proxy-1": {APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}},
	}

	session := &user.SessionState{
		KeyID: "key-1",
		AccessRights: map[string]user.AccessDefinition{
			"proxy-1": {
				APIID: "proxy-1",
				MCPAccessRights: user.MCPAccessRights{
					Tools: user.AccessControlRules{Blocked: []string{"getOrder"}},
				},
			},
		},
	}

	r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{
		"jsonrpc":"2.0",
		"id":1,
		"method":"tools/call",
		"params":{"name":"getOrder","arguments":{"id":"42"}}
	}`))
	r.Header.Set("Content-Type", "application/json")
	httpctx.SetMCPProxyCallerAPIID(r, "proxy-1")
	tykctx.SetSession(r, session, false, false, false)

	w := httptest.NewRecorder()
	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	err, code := mw.ProcessRequest(w, r, nil)

	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "tool 'getOrder' is not available")
	assert.False(t, called)
	assert.Equal(t, "tools/call", ctxGetMCPMethod(r))
	assert.Equal(t, "tool", ctxGetMCPPrimitiveType(r))
	assert.Equal(t, "getOrder", ctxGetMCPPrimitiveName(r))
}

func TestRESTAsMCPPolicy_FiltersToolsListResponse(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"jsonrpc":"2.0",
		"id":1,
		"result":{"tools":[{"name":"getOrder"},{"name":"deleteOrder"}]}
	}`)
	capture := newCapturedResponseWriter()
	capture.Header().Set("Content-Type", "application/json")
	_, err := capture.Write(body)
	require.NoError(t, err)

	policyCtx := &restAsMCPPolicyContext{
		hasAccess:  true,
		listConfig: mcp.ListFilterConfigs["tools"],
		accessDef: user.AccessDefinition{
			MCPAccessRights: user.MCPAccessRights{
				Tools: user.AccessControlRules{Allowed: []string{"getOrder"}},
			},
		},
	}

	policyCtx.filterListResponse(capture)

	assert.Contains(t, capture.body.String(), "getOrder")
	assert.NotContains(t, capture.body.String(), "deleteOrder")
}

func TestRESTAsMCPPolicy_EndpointRateLimitBlocksToolCall(t *testing.T) {
	spec := buildTestAdapterSpec()
	spec.MCPPrimitives = map[string]string{
		"tool:getOrder": "/mcp-tool:orders.lookup",
	}
	var err error
	spec.MCPSDKAdapter, err = mcpadapter.NewSDKAdapter(mcpadapter.SDKServerConfig{
		Name:  spec.Name,
		Tools: spec.DerivedTools,
		CallTool: func(_ context.Context, _ *oas.DerivedTool, _ map[string]any) (*mcpadapter.Recorder, error) {
			return mcpadapter.NewRecorder(), nil
		},
	})
	require.NoError(t, err)

	var cfg config.Config
	require.NoError(t, config.WriteDefault("", &cfg))
	drlManager := &drl.DRL{RequestTokenValue: 1}
	drlManager.SetCurrentTokenValue(1)

	gw := &Gateway{ctx: context.Background()}
	gw.config.Store(cfg)
	gw.SessionLimiter = NewSessionLimiter(context.Background(), &cfg, drlManager, &cfg.ExternalServices)
	gw.apisByID = map[string]*APISpec{
		"proxy-1": {APIDefinition: &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}},
	}

	accessDef := user.AccessDefinition{
		APIID: "proxy-1",
		Endpoints: user.Endpoints{
			{
				Path: "/mcp-tool:orders.lookup",
				Methods: user.EndpointMethods{
					{Name: http.MethodPost, Limit: user.RateLimit{Rate: 1, Per: 60}},
				},
			},
		},
	}
	session := &user.SessionState{
		KeyID: "rest-as-mcp-rate-limit-key",
		AccessRights: map[string]user.AccessDefinition{
			"proxy-1": accessDef,
		},
	}

	mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	makeRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{
			"jsonrpc":"2.0",
			"id":1,
			"method":"tools/call",
			"params":{"name":"getOrder","arguments":{"id":"42"}}
		}`))
		r.Header.Set("Content-Type", "application/json")
		httpctx.SetMCPProxyCallerAPIID(r, "proxy-1")
		tykctx.SetSession(r, session, false, false, false)
		return r
	}

	first := httptest.NewRecorder()
	err, code := mw.ProcessRequest(first, makeRequest(), nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)

	second := httptest.NewRecorder()
	err, code = mw.ProcessRequest(second, makeRequest(), nil)
	require.NoError(t, err)
	assert.Equal(t, middleware.StatusRespond, code)
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Contains(t, second.Body.String(), "Rate Limit Exceeded")
}

func buildRESTSpecForMCPToolViewTest() *APISpec {
	def := &apidef.APIDefinition{
		APIID: "rest-views",
		Name:  "orders",
		OrgID: "org-1",
		IsOAS: true,
	}

	return &APISpec{
		APIDefinition: def,
		OAS: oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "orders", Version: "1.0.0"},
				Paths: openapi3.NewPaths(openapi3.WithPath("/orders", &openapi3.PathItem{
					Get: &openapi3.Operation{
						OperationID: "list_orders",
						Summary:     "list orders",
						Parameters: openapi3.Parameters{
							&openapi3.ParameterRef{Value: &openapi3.Parameter{
								Name:   "status",
								In:     openapi3.ParameterInQuery,
								Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
							}},
						},
					},
					Post: &openapi3.Operation{
						OperationID: "create_order_source",
						Summary:     "create order",
						Parameters: openapi3.Parameters{
							&openapi3.ParameterRef{Value: &openapi3.Parameter{
								Name:   "customer_id",
								In:     openapi3.ParameterInQuery,
								Schema: &openapi3.SchemaRef{Value: openapi3.NewStringSchema()},
							}},
						},
					},
				})),
			},
		},
	}
}

func buildMCPProxySpecForToolViewTest(apiID, orgID, restAPIID string, mcpServer *oas.TykMCPServer) *APISpec {
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: apiID,
			Name:  apiID,
			OrgID: orgID,
			Proxy: apidef.ProxyConfig{TargetURL: oas.AdapterLoopURL(restAPIID)},
		},
		OAS: *buildMCPProxyOASForToolViewTest(apiID, orgID, restAPIID, mcpServer),
	}
}

func buildMCPProxyOASForToolViewTest(apiID, orgID, restAPIID string, mcpServer *oas.TykMCPServer) *oas.OAS {
	doc := &oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: apiID, Version: "1.0.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	doc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:    apiID,
			Name:  apiID,
			OrgID: orgID,
		},
		Upstream: oas.Upstream{URL: oas.AdapterLoopURL(restAPIID)},
	})
	if mcpServer != nil {
		doc.SetTykMCPServerExtension(mcpServer)
	}
	return doc
}

func derivedToolNames(tools []oas.DerivedTool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
