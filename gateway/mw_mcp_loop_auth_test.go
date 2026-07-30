package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
)

func TestMCPLoopAuthBypass_Branches(t *testing.T) {
	source := restSourceSpec("rest-1", "org-1", true)
	snapshot, err := pairing.NewSnapshot([]pairing.Record{{
		SourceRESTAPIID:  "rest-1",
		SourceOrgID:      "org-1",
		CallerProxyAPIID: "proxy-1",
		CallerProxyOrgID: "org-1",
	}})
	require.NoError(t, err)

	gw := &Gateway{}
	gw.mcpPairingIndex.Set(snapshot)

	tests := []struct {
		name        string
		spec        *APISpec
		trust       *mcpAdapterLoopTrust
		wantBypass  bool
		wantSession bool
		wantCode    int
		wantError   bool
	}{
		{
			name:     "no flag pass-through",
			spec:     source,
			wantCode: http.StatusOK,
		},
		{
			name: "matched trust installs loop session",
			spec: source,
			trust: &mcpAdapterLoopTrust{
				SourceRESTAPIID:  "rest-1",
				AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-1"),
				CallerProxyAPIID: "proxy-1",
			},
			wantBypass:  true,
			wantSession: true,
			wantCode:    http.StatusOK,
		},
		{
			name: "REST API ID mismatch returns forbidden",
			spec: source,
			trust: &mcpAdapterLoopTrust{
				SourceRESTAPIID:  "rest-2",
				AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-1"),
				CallerProxyAPIID: "proxy-1",
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name: "adapter API ID mismatch returns forbidden",
			spec: source,
			trust: &mcpAdapterLoopTrust{
				SourceRESTAPIID:  "rest-1",
				AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-2"),
				CallerProxyAPIID: "proxy-1",
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name: "forged proxy ID returns forbidden",
			spec: source,
			trust: &mcpAdapterLoopTrust{
				SourceRESTAPIID:  "rest-1",
				AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-1"),
				CallerProxyAPIID: "proxy-forged",
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
		{
			name: "missing pairing record returns forbidden",
			spec: restSourceSpec("rest-unpaired", "org-1", true),
			trust: &mcpAdapterLoopTrust{
				SourceRESTAPIID:  "rest-unpaired",
				AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-unpaired"),
				CallerProxyAPIID: "proxy-1",
			},
			wantCode:  http.StatusForbidden,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &MCPLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: tt.spec, Gw: gw}}
			req := httptest.NewRequest(http.MethodGet, "/orders", nil)
			if tt.trust != nil {
				ctxSetMCPAdapterLoopTrust(req, *tt.trust)
			}

			err, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCode, code)

			assert.Equal(t, tt.wantBypass, ctxGetRequestStatus(req) == StatusOkAndIgnore)
			assert.Equal(t, tt.wantBypass, ctxMCPAdapterLoopAuthBypassed(req))
			assert.Equal(t, tt.wantSession, ctxGetSession(req) != nil)
			if tt.wantSession {
				assert.Equal(t, "org-1", ctxGetSession(req).OrgID)
				assert.Equal(t, "mcp-loop:rest-1__mcp-server:proxy-1", ctxGetSession(req).KeyID)
			}
		})
	}
}

func TestMCPLoopAuthBypass_PreAuthorizesThenRestoreClearsBypassStatus(t *testing.T) {
	source := restSourceSpec("rest-1", "org-1", true)
	snapshot, err := computeMCPPairing([]*APISpec{
		source,
		pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil),
	})
	require.NoError(t, err)

	gw := &Gateway{}
	gw.mcpPairingIndex.Set(snapshot)

	req := httptest.NewRequest(http.MethodGet, "/orders", nil)
	ctxSetMCPAdapterLoopTrust(req, mcpAdapterLoopTrust{
		SourceRESTAPIID:  "rest-1",
		AdapterAPIID:     pairing.CanonicalAdapterAPIID("rest-1"),
		CallerProxyAPIID: "proxy-1",
	})

	bypass := &MCPLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: source, Gw: gw}}
	restore := &MCPLoopAuthRestoreMiddleware{BaseMiddleware: &BaseMiddleware{Spec: source, Gw: gw}}

	err, code := bypass.ProcessRequest(httptest.NewRecorder(), req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, StatusOkAndIgnore, ctxGetRequestStatus(req))

	err, code = restore.ProcessRequest(httptest.NewRecorder(), req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, StatusOk, ctxGetRequestStatus(req))
	assert.False(t, ctxMCPAdapterLoopAuthBypassed(req))
}

func TestMCPLoopAuth_EnabledForSpec(t *testing.T) {
	source := restSourceSpec("rest-1", "org-1", true)
	unpaired := restSourceSpec("rest-2", "org-1", true)
	proxy := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	synthetic := buildSyntheticAdapterForRuntimeTest(t)

	snapshot, err := pairing.NewSnapshot([]pairing.Record{{
		SourceRESTAPIID:  source.APIID,
		SourceOrgID:      source.OrgID,
		CallerProxyAPIID: proxy.APIID,
		CallerProxyOrgID: proxy.OrgID,
	}})
	require.NoError(t, err)

	pairedGateway := &Gateway{}
	pairedGateway.mcpPairingIndex.Set(snapshot)
	emptyGateway := &Gateway{}

	tests := []struct {
		name string
		gw   *Gateway
		spec *APISpec
		want bool
	}{
		{name: "paired source REST spec", gw: pairedGateway, spec: source, want: true},
		{name: "unpaired REST spec when another pairing exists", gw: pairedGateway, spec: unpaired, want: false},
		{name: "source REST spec with empty pairing index", gw: emptyGateway, spec: source, want: false},
		{name: "paired MCP proxy", gw: pairedGateway, spec: proxy, want: false},
		{name: "synthetic adapter", gw: pairedGateway, spec: synthetic, want: false},
		{name: "nil spec", gw: pairedGateway, want: false},
		{name: "nil gateway", spec: source, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bypass := &MCPLoopAuthBypassMiddleware{BaseMiddleware: &BaseMiddleware{Spec: tt.spec, Gw: tt.gw}}
			restore := &MCPLoopAuthRestoreMiddleware{BaseMiddleware: &BaseMiddleware{Spec: tt.spec, Gw: tt.gw}}

			assert.Equal(t, tt.want, bypass.EnabledForSpec())
			assert.Equal(t, tt.want, restore.EnabledForSpec())
		})
	}
}
