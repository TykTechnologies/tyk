package gateway

import (
	"net/http"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	ctxpkg "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// ensureConfigGlobal stubs config.Global so ctx.SetSession's variadic
// fall-through path (which calls config.Global().HashKeys when len(hashKey)==1)
// does not panic in standalone unit tests that don't spin up a Gateway.
// This is a known wart in ctx.SetSession's signature, not a bug in the
// middleware; production code reaches this path via Gateway.Init which
// installs config.Global itself.
func ensureConfigGlobal(t *testing.T) {
	t.Helper()
	if config.Global == nil {
		config.Global = func() config.Config { return config.Config{} }
	}
}

// newTestMCPCallerAuthMW constructs a middleware whose Spec opts in to
// AcceptMCPLoopCallers and lists the given Proxy APIIDs in the back-ref.
// The Gw is wired with an apisByID map so the OAS-extension lookup path
// is exercised; callers can register extra "caller" APISpecs to drive the
// callerHasMCPProxyExtension branch.
func newTestMCPCallerAuthMW(t *testing.T, accept bool, proxies []string, callers map[string]*APISpec) *MCPCallerAuthMiddleware {
	t.Helper()

	srcOAS := oas.OAS{}
	srcOAS.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			AcceptMCPLoopCallers: accept,
			MCPProxies:           proxies,
		},
	})
	src := &APISpec{
		APIDefinition: &apidef.APIDefinition{APIID: "source-1", IsOAS: true},
		OAS:           srcOAS,
	}

	apisByID := map[string]*APISpec{"source-1": src}
	for id, sp := range callers {
		apisByID[id] = sp
	}

	gw := &Gateway{
		apisMu:   sync.RWMutex{},
		apisByID: apisByID,
	}

	return &MCPCallerAuthMiddleware{
		BaseMiddleware: &BaseMiddleware{Spec: src, Gw: gw},
	}
}

// callerWithMCPProxyExt builds an APISpec whose OAS Server block carries
// a non-nil MCPProxy extension — the shape the Phase A2/A3 work persists
// for genuine MCP Proxy APIDefs.
func callerWithMCPProxyExt(apiID string) *APISpec {
	o := oas.OAS{}
	o.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			MCPProxy: &oas.MCPProxy{},
		},
	})
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{APIID: apiID, IsOAS: true},
		OAS:           o,
	}
}

// callerWithoutMCPProxyExt is the negative shape: a regular OAS APIDef
// with no MCPProxy extension. Used to drive the §11 "caller has no
// MCPProxy extension" no-op branch.
func callerWithoutMCPProxyExt(apiID string) *APISpec {
	o := oas.OAS{}
	o.SetTykExtension(&oas.XTykAPIGateway{Server: oas.Server{}})
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{APIID: apiID, IsOAS: true},
		OAS:           o,
	}
}

func TestMCPCallerAuth_Name(t *testing.T) {
	m := &MCPCallerAuthMiddleware{BaseMiddleware: &BaseMiddleware{}}
	if got, want := m.Name(), "MCPCallerAuth"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestMCPCallerAuth_EnabledForSpec_FalseWhenFlagOff(t *testing.T) {
	m := newTestMCPCallerAuthMW(t, false, nil, nil)
	if m.EnabledForSpec() {
		t.Fatalf("EnabledForSpec() = true, want false when AcceptMCPLoopCallers=false")
	}
}

func TestMCPCallerAuth_EnabledForSpec_TrueWhenFlagOn(t *testing.T) {
	m := newTestMCPCallerAuthMW(t, true, nil, nil)
	if !m.EnabledForSpec() {
		t.Fatalf("EnabledForSpec() = false, want true when AcceptMCPLoopCallers=true")
	}
}

func TestMCPCallerAuth_EnabledForSpec_NoTykExt(t *testing.T) {
	// APISpec with an OAS that has no Tyk extension at all.
	src := &APISpec{
		APIDefinition: &apidef.APIDefinition{APIID: "source-1", IsOAS: true},
		OAS:           oas.OAS{},
	}
	m := &MCPCallerAuthMiddleware{BaseMiddleware: &BaseMiddleware{Spec: src}}
	if m.EnabledForSpec() {
		t.Fatalf("EnabledForSpec() = true, want false when Tyk extension absent")
	}
}

func TestMCPCallerAuth_ProcessRequest_TrustSetsSessionAndSkipAuth(t *testing.T) {
	ensureConfigGlobal(t)
	callers := map[string]*APISpec{
		"proxy-1": callerWithMCPProxyExt("proxy-1"),
	}
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, callers)

	r, _ := http.NewRequest("POST", "http://source/", nil)
	httpctx.SetSelfLooping(r, true)
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-1"})
	r.Header.Set("X-Tyk-MCP-Context",
		`{"agent_id":"agent-7","tool_name":"users__get","request_id":"req-42"}`)

	err, code := m.ProcessRequest(nil, r, nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("ProcessRequest err=%v code=%d, want (nil, 200)", err, code)
	}

	// The synthetic session must be visible via ctx.GetSession.
	sess := ctxpkg.GetSession(r)
	if sess == nil {
		t.Fatalf("expected synthetic session set on Trust, got nil")
	}
	if got, want := sess.KeyID, "mcp:proxy-1:agent-7"; got != want {
		t.Errorf("session.KeyID = %q, want %q", got, want)
	}
	if got, want := sess.Alias, "mcp:proxy-1"; got != want {
		t.Errorf("session.Alias = %q, want %q", got, want)
	}
	if got, want := sess.MetaData["mcp_proxy_apiid"], "proxy-1"; got != want {
		t.Errorf("metadata mcp_proxy_apiid = %v, want %q", got, want)
	}
	if got, want := sess.MetaData["mcp_agent_id"], "agent-7"; got != want {
		t.Errorf("metadata mcp_agent_id = %v, want %q", got, want)
	}
	if got, want := sess.MetaData["mcp_tool_name"], "users__get"; got != want {
		t.Errorf("metadata mcp_tool_name = %v, want %q", got, want)
	}
	if got, want := sess.MetaData["mcp_request_id"], "req-42"; got != want {
		t.Errorf("metadata mcp_request_id = %v, want %q", got, want)
	}

	// Skip-auth flag must be visible to downstream auth MWs.
	if !httpctx.IsAuthSkipped(r) {
		t.Fatalf("expected IsAuthSkipped(r) = true after Trust")
	}
}

func TestMCPCallerAuth_ProcessRequest_NoOp_FlagOff(t *testing.T) {
	callers := map[string]*APISpec{"proxy-1": callerWithMCPProxyExt("proxy-1")}
	m := newTestMCPCallerAuthMW(t, false, []string{"proxy-1"}, callers)

	r, _ := http.NewRequest("GET", "http://source/", nil)
	httpctx.SetSelfLooping(r, true)
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-1"})

	err, code := m.ProcessRequest(nil, r, nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("ProcessRequest err=%v code=%d, want (nil, 200)", err, code)
	}
	if ctxpkg.GetSession(r) != nil {
		t.Errorf("no session expected on NoOp")
	}
	if httpctx.IsAuthSkipped(r) {
		t.Errorf("IsAuthSkipped should be false on NoOp")
	}
}

func TestMCPCallerAuth_ProcessRequest_NoOp_NotSelfLooping(t *testing.T) {
	callers := map[string]*APISpec{"proxy-1": callerWithMCPProxyExt("proxy-1")}
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, callers)

	r, _ := http.NewRequest("GET", "http://source/", nil)
	// IsSelfLooping not set -> external request -> NoOp.
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-1"})

	_, code := m.ProcessRequest(nil, r, nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if ctxpkg.GetSession(r) != nil {
		t.Errorf("no session expected when not self-looping")
	}
	if httpctx.IsAuthSkipped(r) {
		t.Errorf("IsAuthSkipped should be false when not self-looping")
	}
}

func TestMCPCallerAuth_ProcessRequest_NoOp_CallerLacksExtension(t *testing.T) {
	callers := map[string]*APISpec{
		// Caller is registered but does NOT carry the MCPProxy extension.
		"proxy-1": callerWithoutMCPProxyExt("proxy-1"),
	}
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, callers)

	r, _ := http.NewRequest("GET", "http://source/", nil)
	httpctx.SetSelfLooping(r, true)
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-1"})

	_, _ = m.ProcessRequest(nil, r, nil)
	if ctxpkg.GetSession(r) != nil {
		t.Errorf("no session expected when caller has no MCPProxy ext")
	}
	if httpctx.IsAuthSkipped(r) {
		t.Errorf("IsAuthSkipped should be false when caller has no MCPProxy ext")
	}
}

func TestMCPCallerAuth_ProcessRequest_NoOp_CallerNotInBackRef(t *testing.T) {
	// Caller HAS the extension but its APIID is NOT in the source's
	// MCPProxies back-ref — multi-tenant safety must reject.
	callers := map[string]*APISpec{
		"proxy-other": callerWithMCPProxyExt("proxy-other"),
	}
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, callers)

	r, _ := http.NewRequest("GET", "http://source/", nil)
	httpctx.SetSelfLooping(r, true)
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-other"})

	_, _ = m.ProcessRequest(nil, r, nil)
	if ctxpkg.GetSession(r) != nil {
		t.Errorf("no session expected when caller not in back-ref")
	}
	if httpctx.IsAuthSkipped(r) {
		t.Errorf("IsAuthSkipped should be false when caller not in back-ref")
	}
}

func TestMCPCallerAuth_ProcessRequest_NoOp_CallerLookupMiss(t *testing.T) {
	// Source opts in and lists proxy-1 in back-ref, but apisByID has no
	// entry for proxy-1 (simulates apisHandlesByID reload race).
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, nil)

	r, _ := http.NewRequest("GET", "http://source/", nil)
	httpctx.SetSelfLooping(r, true)
	r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: "proxy-1"})

	_, _ = m.ProcessRequest(nil, r, nil)
	if ctxpkg.GetSession(r) != nil {
		t.Errorf("no session expected on caller lookup miss (fail closed)")
	}
	if httpctx.IsAuthSkipped(r) {
		t.Errorf("IsAuthSkipped should be false on caller lookup miss")
	}
}

func TestMCPCallerAuth_ProcessRequest_NilRequest(t *testing.T) {
	m := newTestMCPCallerAuthMW(t, true, []string{"proxy-1"}, nil)
	err, code := m.ProcessRequest(nil, nil, nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("ProcessRequest(nil) err=%v code=%d, want (nil, 200)", err, code)
	}
}
