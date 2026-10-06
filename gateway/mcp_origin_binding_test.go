package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/mcp/pairing"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPOriginVerifiedPairingAndCurrentSession(t *testing.T) {
	gw, adapterSpec, _ := syntheticAdapterGatewayForCallTest(t)
	gw.apisHandlesByID.Store(adapterSpec.APIID, &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guard := &MCPOriginValidationMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
		_, status := guard.ProcessRequest(w, r, nil)
		if status != http.StatusOK {
			return
		}
		mw := &JSONRPCMiddleware{BaseMiddleware: &BaseMiddleware{Spec: adapterSpec, Gw: gw}}
		_, _ = mw.ProcessRequest(w, r, nil)
	})})
	var mu sync.Mutex
	var markers []string
	gw.apisHandlesByID.Store("rest-1", &ChainObject{ThisHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := mcpAdapterParentRequestFromContext(r.Context())
		require.NotNil(t, parent)
		marker := parent.Header.Get("X-Request-Marker")
		mu.Lock()
		markers = append(markers, marker)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"marker":%q}`, marker)
	})})
	for _, id := range []string{"proxy-1", "proxy-2"} {
		gw.apisByID[id].UseKeylessAccess = true
		gw.apisByID[id].MCP = &apidef.MCPConfig{TrustedOrigins: []string{"https://" + id + ".example"}}
	}
	serve := func(callerID, origin, body, sid, marker string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://gateway/public/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("X-Request-Marker", marker)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if sid != "" {
			r.Header.Set("Mcp-Session-Id", sid)
		}
		caller := gw.apisByID[callerID]
		rec := httptest.NewRecorder()
		guard := &MCPOriginValidationMiddleware{BaseMiddleware: &BaseMiddleware{Spec: caller, Gw: gw}}
		_, status := guard.ProcessRequest(rec, r, nil)
		if status != http.StatusOK {
			return rec
		}
		h, _, ok := gw.findInternalHTTPHandlerForLoop("rest-1", caller, r)
		if !ok {
			t.Error("missing paired handler")
			return rec
		}
		h.ServeHTTP(rec, r)
		return rec
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"orders","arguments":{}}}`
	for _, origin := range []string{"", "http://gateway", "https://proxy-1.example"} {
		initialized := serve("proxy-1", origin, init, "", "initialize")
		require.Equal(t, 200, initialized.Code, initialized.Body.String())
		sid := initialized.Header().Get("Mcp-Session-Id")
		require.NotEmpty(t, sid)
		listed := serve("proxy-1", origin, list, sid, "list")
		require.Equal(t, 200, listed.Code, listed.Body.String())
		require.Contains(t, listed.Body.String(), `"orders"`)
		called := serve("proxy-1", origin, call, sid, "current-call")
		require.Equal(t, 200, called.Code, called.Body.String())
		require.Contains(t, called.Body.String(), "current-call")
		replay := serve("proxy-2", "https://proxy-2.example", list, sid, "replay")
		require.Equal(t, 403, replay.Code, replay.Body.String())
		require.Equal(t, 403, serve("proxy-1", "https://proxy-2.example", "invalid-json", sid, "bad-origin").Code)
	}
	require.Equal(t, []string{"current-call", "current-call", "current-call"}, markers)
}

func TestMCPOriginHopRejectsChangedOrForgedProvenance(t *testing.T) {
	gw, target, _ := syntheticAdapterGatewayForCallTest(t)
	caller := gw.apisByID["proxy-1"]
	caller.UseKeylessAccess = true
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"missing", func(r *http.Request) { setCtxValue(r, mcpOriginHopKey, mcpOriginHop{}) }},
		{"caller-only", func(r *http.Request) {
			setCtxValue(r, mcpOriginHopKey, mcpOriginHop{})
			ctxSetMCPAdapterCallerProxyID(r, caller.APIID)
		}},
		{"changed-origin", func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }},
		{"duplicate", func(r *http.Request) { r.Header.Add("Origin", "https://trusted.example") }},
		{"blank", func(r *http.Request) { r.Header.Set("Origin", "") }},
		{"absent", func(r *http.Request) { r.Header.Del("Origin") }},
		{"wrong-source", func(r *http.Request) {
			hop := r.Context().Value(mcpOriginHopKey).(mcpOriginHop)
			hop.SourceRESTAPIID = "other"
			setCtxValue(r, mcpOriginHopKey, hop)
		}},
		{"wrong-adapter", func(r *http.Request) {
			hop := r.Context().Value(mcpOriginHopKey).(mcpOriginHop)
			hop.AdapterAPIID = "other"
			setCtxValue(r, mcpOriginHopKey, hop)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://gateway/mcp", strings.NewReader("invalid-json"))
			req.Header.Set("Origin", "https://trusted.example")
			acceptMCPOrigin(req, caller, "https://trusted.example")
			require.True(t, establishMCPAdapterOriginHop(req, gw, caller, target))
			test.mutate(req)
			guard := &MCPOriginValidationMiddleware{BaseMiddleware: &BaseMiddleware{Spec: target, Gw: gw}}
			rec := httptest.NewRecorder()
			_, _ = guard.ProcessRequest(rec, req, nil)
			require.Equal(t, 403, rec.Code)
			require.Equal(t, int64(len("invalid-json")), req.ContentLength)
		})
	}
	req := httptest.NewRequest("POST", "http://gateway/mcp", nil)
	acceptMCPOrigin(req, caller, "")
	require.True(t, establishMCPAdapterOriginHop(req, gw, caller, target))
	source := gw.apisByID["rest-1"]
	_, _, _ = gw.findInternalHTTPHandlerForLoop(target.APIID, source, req)
	require.False(t, validMCPAdapterOriginHop(req, gw, target), "unrelated internal loop reused a prior proof")
	acceptMCPOrigin(req, caller, "")
	require.True(t, establishMCPAdapterOriginHop(req, gw, caller, target))
	gw.mcpPairingIndex.Set(pairing.Snapshot{})
	require.False(t, validMCPAdapterOriginHop(req, gw, target))
}

func TestMCPAdapterSessionOwnerScopesTrustedIdentity(t *testing.T) {
	caller := pairedMCPProxySpec("proxy-1", "org-1", "rest-1", nil)
	req := httptest.NewRequest("POST", "http://gateway", nil)
	caller.UseKeylessAccess = false
	_, err := mcpAdapterSessionOwner(req, caller)
	require.Error(t, err)
	setSessionForTest(req, &user.SessionState{KeyID: "key-a"})
	owner, err := mcpAdapterSessionOwner(req, caller)
	require.NoError(t, err)
	require.Len(t, owner, 64)
	require.NotContains(t, owner, "key-a")
	req.Header.Set("Authorization", "untrusted-header-change")
	same, err := mcpAdapterSessionOwner(req, caller)
	require.NoError(t, err)
	require.Equal(t, owner, same)
	setSessionForTest(req, &user.SessionState{KeyID: "key-b"})
	different, err := mcpAdapterSessionOwner(req, caller)
	require.NoError(t, err)
	assert.NotEqual(t, owner, different)
	caller.UseKeylessAccess = true
	anon, err := mcpAdapterSessionOwner(req, caller)
	require.NoError(t, err)
	assert.NotEqual(t, owner, anon)
	caller.APIID = "proxy-2"
	other, err := mcpAdapterSessionOwner(req, caller)
	require.NoError(t, err)
	assert.NotEqual(t, anon, other)
}
