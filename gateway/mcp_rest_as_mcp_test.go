package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	mcpadapter "github.com/TykTechnologies/tyk/internal/mcp/adapter"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
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

func TestAdapterInline_DispatchesEachMethod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		method     string
		assertBody func(t *testing.T, env map[string]any)
	}{
		{
			name:   "initialize",
			method: mcpadapter.MethodInitialize,
			assertBody: func(t *testing.T, env map[string]any) {
				res := env["result"].(map[string]any)
				assert.Equal(t, mcpadapter.ProtocolVersion, res["protocolVersion"])
			},
		},
		{
			name:   "ping",
			method: mcpadapter.MethodPing,
			assertBody: func(t *testing.T, env map[string]any) {
				assert.Empty(t, env["result"].(map[string]any))
			},
		},
		{
			name:   "tools/list",
			method: "tools/list",
			assertBody: func(t *testing.T, env map[string]any) {
				tools := env["result"].(map[string]any)["tools"].([]any)
				require.Len(t, tools, 1)
				assert.Equal(t, "getOrder", tools[0].(map[string]any)["name"])
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: buildTestAdapterSpec()}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

			ok := m.handleAdapterInline(w, r, &JSONRPCRequest{
				JSONRPC: apidef.JsonRPC20,
				Method:  tc.method,
				ID:      1,
			})
			require.True(t, ok)

			var env map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
			tc.assertBody(t, env)
		})
	}
}

func TestAdapterInline_NonAdapterFallsThrough(t *testing.T) {
	t.Parallel()
	def := &apidef.APIDefinition{APIID: "regular", OrgID: "org-1"}
	def.MarkAsMCP()
	spec := &APISpec{APIDefinition: def} // IsSyntheticMCPAdapter false

	m := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp/", nil)

	ok := m.handleAdapterInline(w, r, &JSONRPCRequest{Method: mcpadapter.MethodInitialize})
	assert.False(t, ok)
	assert.Empty(t, w.Body.String())
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
