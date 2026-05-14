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
	}
	def.MCPExposure.Enabled = true

	return &APISpec{
		APIDefinition: def,
		OAS: oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{Title: "orders", Version: "1.0.0"},
				Paths: openapi3.NewPaths(openapi3.WithPath("/orders/{id}", &openapi3.PathItem{
					Get: &openapi3.Operation{
						OperationID: "getOrder",
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

func waitForGatewayToolListChanged(t *testing.T, changed <-chan struct{}) {
	t.Helper()

	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tools/list_changed notification")
	}
}

type testMCPPairing struct {
	proxy   map[string]string
	adapter map[string]string
}

func newTestMCPPairing(restID, proxyID, adapterID string) testMCPPairing {
	return testMCPPairing{
		proxy:   map[string]string{restID: proxyID},
		adapter: map[string]string{restID: adapterID},
	}
}

func (p testMCPPairing) ProxyForREST(restAPIID string) (string, bool) {
	v, ok := p.proxy[restAPIID]
	return v, ok
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
	assert.Equal(t, true, tools["listChanged"])
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
	waitForGatewayToolListChanged(t, changed)

	list, err := session.ListTools(context.Background(), &mcpsdk.ListToolsParams{})
	require.NoError(t, err)
	require.Len(t, list.Tools, 1)
	assert.Equal(t, "getOrder", list.Tools[0].Name)
	assert.Equal(t, "fetch an order by id", list.Tools[0].Description)
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
			pairing:  pairing.Static{"rest-1": "proxy-1"},
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
			spec.MCPExposure.Enabled = true

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
	spec.MCPExposure.Enabled = true

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
	exposed := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest"}}
	exposed.MCPExposure.Enabled = true
	plain := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest2"}}

	assert.True(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: exposed}}).EnabledForSpec())
	assert.False(t, (&MCPLoopAuthBypass{BaseMiddleware: &BaseMiddleware{Spec: plain}}).EnabledForSpec())
}

// TestComputeMCPPairing covers the pure pairing-rebuild logic without
// any Gateway plumbing — it operates on the same APISpec map structure
// the loader holds, but otherwise has no dependencies.
func TestComputeMCPPairing(t *testing.T) {
	t.Parallel()

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1"}}
	rest.MCPExposure.Enabled = true

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

	pairingMap, adapterMap := computeMCPPairing(specs)
	assert.Equal(t, "proxy-1", pairingMap["rest-1"])
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

	pairingMap, _ := computeMCPPairing(specs)
	_, paired := pairingMap["rest-1"]
	assert.False(t, paired, "cross-org pairing must be refused")
}

func TestComputeMCPPairing_DuplicateProxyTargetsRefused(t *testing.T) {
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

	pairingMap, adapterMap := computeMCPPairing(specs)
	_, paired := pairingMap["rest-1"]
	assert.False(t, paired, "duplicate proxy targets for one REST API must be ambiguous")
	assert.Equal(t, oas.AdapterAPIID("rest-1"), adapterMap["rest-1"])
}

func TestCallMCPAdapterTool_RequiresActualCallerProxyToMatchPairing(t *testing.T) {
	t.Parallel()

	adapterID := oas.AdapterAPIID("rest-1")
	idx := pairing.New()
	idx.Set(map[string]string{"rest-1": "proxy-real"}, map[string]string{"rest-1": adapterID})

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
	assert.Contains(t, err.Error(), "caller proxy")
}

func TestHandleDeleteAPI_RefusesRESTSourceWithPairedMCPProxy(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.config.Store(config.Config{AppPath: t.TempDir()})

	rest := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "rest-1", OrgID: "org-1", IsOAS: true}}
	proxyDef := &apidef.APIDefinition{APIID: "proxy-1", OrgID: "org-1"}
	proxyDef.Proxy.TargetURL = "tyk://" + oas.AdapterAPIID("rest-1")
	proxy := &APISpec{APIDefinition: proxyDef}

	gw.apisByID = map[string]*APISpec{
		rest.APIID:  rest,
		proxy.APIID: proxy,
	}

	obj, code := gw.handleDeleteAPI("rest-1")

	assert.Equal(t, http.StatusConflict, code)
	assert.Contains(t, obj.(apiStatusMessage).Message, "proxy-1")
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
		MCPPrimitives: []user.MCPPrimitiveLimit{
			{Type: mcp.PrimitiveTypeTool, Name: "getOrder", Limit: user.RateLimit{Rate: 1, Per: 60}},
		},
	}
	synthesizeMCPEndpoints(&accessDef)
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
