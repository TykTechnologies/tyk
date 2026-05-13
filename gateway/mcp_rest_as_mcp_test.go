package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
	"github.com/TykTechnologies/tyk/internal/middleware"
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
			pairing: pairing.Static{"rest-1": "proxy-1"},
			stampTrust: &httpctx.MCPLoopTrust{
				ProxyAPIID:   "proxy-1",
				RESTAPIID:    "rest-1",
				AdapterAPIID: oas.AdapterAPIID("rest-1"),
			},
			wantCode: http.StatusOK,
			wantSess: true,
		},
		{
			name:    "mismatched-flag-returns-403",
			pairing: pairing.Static{"rest-1": "proxy-real"},
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
