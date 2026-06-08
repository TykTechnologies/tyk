package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// fakeRPCLoader is a hand-written RPCDataLoader for exercising the registry's
// RPC branch without a live MDCB connection.
type fakeRPCLoader struct {
	payload     string
	gotOrgID    string
	gotTags     []string
	callerCount int
}

func (f *fakeRPCLoader) Connect() bool                                 { return true }
func (f *fakeRPCLoader) GetApiDefinitions(_ string, _ []string) string { return "" }
func (f *fakeRPCLoader) GetPolicies(_ string) string                   { return "" }
func (f *fakeRPCLoader) GetClientIdPs(orgID string, tags []string) string {
	f.callerCount++
	f.gotOrgID = orgID
	f.gotTags = tags
	return f.payload
}

// mustWriteJSON writes a mock HTTP response body, failing the test on error.
// Runs in the httptest server goroutine, so it uses Errorf (not Fatalf).
func mustWriteJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("mock write failed: %v", err)
	}
}

// The gateway feed (RPC GetClientIdPs) delivers a bare JSON array of records
// using the dashboard wire field names (client_idp_id, org_id, jwks_uri, ...).
func TestUnmarshalIdPs_BareArray(t *testing.T) {
	payload := []byte(`[
	  {
	    "client_idp_id": "idp-1",
	    "org_id": "org-1",
	    "name": "keycloak",
	    "issuer": "https://issuer.example",
	    "jwks_uri": "https://issuer.example/jwks",
	    "api_mappings": {
	      "api-a": { "scope_to_policy": { "read": "pol-read", "write": "pol-write" } }
	    }
	  }
	]`)

	idps, err := unmarshalIdPs(payload)
	if err != nil {
		t.Fatalf("unmarshalIdPs returned error: %v", err)
	}
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0]
	if idp.ID != "idp-1" {
		t.Errorf("ID: want idp-1, got %q", idp.ID)
	}
	if idp.OrgID != "org-1" {
		t.Errorf("OrgID: want org-1, got %q", idp.OrgID)
	}
	if idp.Name != "keycloak" {
		t.Errorf("Name: want keycloak, got %q", idp.Name)
	}
	if idp.Issuer != "https://issuer.example" {
		t.Errorf("Issuer: want https://issuer.example, got %q", idp.Issuer)
	}
	if idp.JWKSURI != "https://issuer.example/jwks" {
		t.Errorf("JWKSURI: want https://issuer.example/jwks, got %q", idp.JWKSURI)
	}
	sm, ok := idp.APIMappings["api-a"]
	if !ok {
		t.Fatalf("APIMappings missing api-a: %#v", idp.APIMappings)
	}
	if sm.ScopeToPolicy["read"] != "pol-read" || sm.ScopeToPolicy["write"] != "pol-write" {
		t.Errorf("ScopeToPolicy mismatch: %#v", sm.ScopeToPolicy)
	}
}

// The direct-Dashboard HTTP feed wraps the array in a NodeResponseOK envelope
// {"Status","Message":[...],"Nonce":"..."}. unmarshalIdPs must tolerate it too.
func TestUnmarshalIdPs_Envelope(t *testing.T) {
	payload := []byte(`{
	  "Status": "OK",
	  "Nonce": "abc123",
	  "Message": [
	    { "client_idp_id": "idp-2", "issuer": "https://i2", "jwks_uri": "https://i2/jwks" }
	  ]
	}`)

	idps, err := unmarshalIdPs(payload)
	if err != nil {
		t.Fatalf("unmarshalIdPs returned error: %v", err)
	}
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}
	if idps[0].ID != "idp-2" {
		t.Errorf("ID: want idp-2, got %q", idps[0].ID)
	}
}

// Empty input is a no-op, not an error (mirrors empty RPC payloads).
func TestUnmarshalIdPs_Empty(t *testing.T) {
	idps, err := unmarshalIdPs(nil)
	if err != nil {
		t.Fatalf("nil input should not error, got %v", err)
	}
	if idps != nil {
		t.Errorf("nil input should return nil slice, got %#v", idps)
	}
}

// With no matched binding, the manual scope map is returned verbatim — the same
// reference, so manual APIs allocate nothing and behave byte-identically.
func TestScopeToPolicyMapForRequest_NoBinding(t *testing.T) {
	manual := map[string]string{"read": "pol-read"}

	got := scopeToPolicyMapForRequest(manual, nil)
	if len(got) != 1 || got["read"] != "pol-read" {
		t.Fatalf("nil binding should return manual unchanged, got %#v", got)
	}

	empty := scopeToPolicyMapForRequest(manual, &Binding{})
	if len(empty) != 1 || empty["read"] != "pol-read" {
		t.Fatalf("empty binding should return manual unchanged, got %#v", empty)
	}
}

// Manual config is authoritative: on a scope-name collision manual wins, and the
// binding only fills scopes the manual map does not define.
func TestScopeToPolicyMapForRequest_ManualWinsBindingFills(t *testing.T) {
	manual := map[string]string{"read": "pol-manual"}
	binding := &Binding{
		IdPID: "idp-1",
		ScopeToPolicy: map[string]string{
			"read":  "pol-binding", // collides with manual -> manual must win
			"write": "pol-write",   // absent from manual -> binding fills it
		},
	}

	got := scopeToPolicyMapForRequest(manual, binding)
	if got["read"] != "pol-manual" {
		t.Errorf("collision: manual must win, got read=%q", got["read"])
	}
	if got["write"] != "pol-write" {
		t.Errorf("fill: binding must fill absent scope, got write=%q", got["write"])
	}
	// The merge must not mutate the caller's manual map.
	if len(manual) != 1 {
		t.Errorf("manual map was mutated: %#v", manual)
	}
}

// A binding with no manual map returns the binding's mapping.
func TestScopeToPolicyMapForRequest_BindingOnly(t *testing.T) {
	binding := &Binding{ScopeToPolicy: map[string]string{"read": "pol-read"}}

	got := scopeToPolicyMapForRequest(nil, binding)
	if len(got) != 1 || got["read"] != "pol-read" {
		t.Fatalf("binding-only mapping wrong: %#v", got)
	}
}

// rebuild builds the reverse index, but the segment-aware backstop drops any
// binding whose api_id is not in the loaded API set, and omits IdPs that retain
// zero surviving mappings entirely.
func TestIdPRegistry_RebuildSegmentBackstop(t *testing.T) {
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"api-a": {},
			"api-b": {},
		},
	}
	r := newIdPRegistry(gw)

	idps := []IdP{
		{
			ID:     "idp-1",
			Issuer: "https://i1",
			APIMappings: map[string]ScopeMapping{
				"api-a": {ScopeToPolicy: map[string]string{"read": "pol-read"}}, // loaded
				"api-c": {ScopeToPolicy: map[string]string{"x": "pol-x"}},       // NOT loaded -> dropped
			},
		},
		{
			ID:     "idp-2",
			Issuer: "https://i2",
			APIMappings: map[string]ScopeMapping{
				"api-z": {ScopeToPolicy: map[string]string{"y": "pol-y"}}, // NOT loaded -> idp omitted
			},
		},
	}

	r.rebuild(idps)

	// api-a is loaded and bound by idp-1.
	bindingsA := r.BindingsForAPI("api-a")
	if len(bindingsA) != 1 {
		t.Fatalf("api-a: want 1 binding, got %d", len(bindingsA))
	}
	if bindingsA[0].IdPID != "idp-1" {
		t.Errorf("api-a binding IdPID: want idp-1, got %q", bindingsA[0].IdPID)
	}
	if bindingsA[0].ScopeToPolicy["read"] != "pol-read" {
		t.Errorf("api-a binding scope map wrong: %#v", bindingsA[0].ScopeToPolicy)
	}

	// api-c was mapped by idp-1 but is not loaded -> no binding.
	if got := r.BindingsForAPI("api-c"); got != nil {
		t.Errorf("api-c: unloaded api must have no bindings, got %#v", got)
	}
	// api-b is loaded but unbound -> no binding.
	if got := r.BindingsForAPI("api-b"); got != nil {
		t.Errorf("api-b: unbound api must have no bindings, got %#v", got)
	}

	// idp-1 retained a mapping -> present. idp-2 had zero surviving -> omitted.
	if _, ok := r.IdP("idp-1"); !ok {
		t.Errorf("idp-1 should be retained")
	}
	if _, ok := r.IdP("idp-2"); ok {
		t.Errorf("idp-2 had zero surviving mappings and must be omitted")
	}
}

// rebuild is build-then-swap: a previous snapshot must be fully replaced.
func TestIdPRegistry_RebuildReplacesSnapshot(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{"api-a": {}}}
	r := newIdPRegistry(gw)

	r.rebuild([]IdP{{ID: "old", APIMappings: map[string]ScopeMapping{"api-a": {}}}})
	r.rebuild([]IdP{{ID: "new", APIMappings: map[string]ScopeMapping{"api-a": {}}}})

	if _, ok := r.IdP("old"); ok {
		t.Errorf("old IdP must be gone after rebuild")
	}
	if _, ok := r.IdP("new"); !ok {
		t.Errorf("new IdP must be present after rebuild")
	}
	if b := r.BindingsForAPI("api-a"); len(b) != 1 || b[0].IdPID != "new" {
		t.Errorf("api-a should bind only the new IdP, got %#v", b)
	}
}

// fetchFromRPC calls the injected loader with the RPC key and decodes the array.
func TestIdPRegistry_FetchFromRPC(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	conf.SlaveOptions.RPCKey = "org-1"
	gw.SetConfig(conf)

	fake := &fakeRPCLoader{payload: `[{"client_idp_id":"idp-1","issuer":"https://i1"}]`}
	r := newIdPRegistry(gw)
	r.rpcLoaderFn = func() RPCDataLoader { return fake }

	idps, err := r.fetchFromRPC()
	if err != nil {
		t.Fatalf("fetchFromRPC error: %v", err)
	}
	if len(idps) != 1 || idps[0].ID != "idp-1" {
		t.Fatalf("decoded IdPs wrong: %#v", idps)
	}
	if fake.gotOrgID != "org-1" {
		t.Errorf("RPC key: want org-1, got %q", fake.gotOrgID)
	}
	if fake.gotTags != nil {
		t.Errorf("non-segmented node must pass no tags, got %#v", fake.gotTags)
	}
}

// A segmented node forwards its tags so MDCB can pre-filter the payload.
func TestIdPRegistry_FetchFromRPC_Segmented(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	conf.SlaveOptions.RPCKey = "org-1"
	conf.DBAppConfOptions.NodeIsSegmented = true
	conf.DBAppConfOptions.Tags = []string{"edge-eu"}
	gw.SetConfig(conf)

	fake := &fakeRPCLoader{payload: ""}
	r := newIdPRegistry(gw)
	r.rpcLoaderFn = func() RPCDataLoader { return fake }

	idps, err := r.fetchFromRPC()
	if err != nil {
		t.Fatalf("fetchFromRPC error: %v", err)
	}
	if idps != nil {
		t.Errorf("empty payload must decode to nil, got %#v", idps)
	}
	if len(fake.gotTags) != 1 || fake.gotTags[0] != "edge-eu" {
		t.Errorf("segmented node must forward tags, got %#v", fake.gotTags)
	}
}

// fetchFromDashboard hits GET /system/clientidps with the gateway auth headers,
// decodes the NodeResponseOK envelope, returns Message, and captures the Nonce.
func TestIdPRegistry_FetchFromDashboard(t *testing.T) {
	var gotPath, gotAuth, gotNodeID, gotSession string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("authorization")
		gotNodeID = r.Header.Get(header.XTykNodeID)
		gotSession = r.Header.Get(header.XTykSessionID)
		w.Header().Set("Content-Type", "application/json")
		mustWriteJSON(t, w, `{"Status":"OK","Nonce":"nonce-new","Message":[`+
			`{"client_idp_id":"idp-1","issuer":"https://i1","jwks_uri":"https://i1/jwks"}]}`)
	}))
	defer srv.Close()

	gw := &Gateway{apisByID: map[string]*APISpec{}, ctx: context.Background()}
	conf := config.Config{}
	conf.UseDBAppConfigs = true
	conf.DisableDashboardZeroConf = true
	conf.DBAppConfOptions.ConnectionString = srv.URL
	conf.NodeSecret = "node-secret-xyz"
	gw.SetConfig(conf)
	gw.SetNodeID("node-1")
	gw.SessionID = "session-1"
	gw.ServiceNonce = "nonce-old"

	r := newIdPRegistry(gw)

	idps, err := r.fetchFromDashboard()
	if err != nil {
		t.Fatalf("fetchFromDashboard error: %v", err)
	}
	if len(idps) != 1 || idps[0].ID != "idp-1" {
		t.Fatalf("decoded IdPs wrong: %#v", idps)
	}
	if gotPath != "/system/clientidps" {
		t.Errorf("endpoint path: want /system/clientidps, got %q", gotPath)
	}
	if gotAuth != "node-secret-xyz" {
		t.Errorf("authorization header: want node secret, got %q", gotAuth)
	}
	if gotNodeID != "node-1" {
		t.Errorf("node id header: want node-1, got %q", gotNodeID)
	}
	if gotSession != "session-1" {
		t.Errorf("session id header: want session-1, got %q", gotSession)
	}
	// The returned nonce must be captured so the node stays in sync — discarding
	// it would desync against the dashboard's per-call createNonce.
	if gw.ServiceNonce != "nonce-new" {
		t.Errorf("ServiceNonce: want nonce-new, got %q", gw.ServiceNonce)
	}
}

// A 403 from the dashboard is a login failure, surfaced as an error so the
// previous registry snapshot is kept.
func TestIdPRegistry_FetchFromDashboard_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		mustWriteJSON(t, w, "nope")
	}))
	defer srv.Close()

	gw := &Gateway{apisByID: map[string]*APISpec{}, ctx: context.Background()}
	conf := config.Config{}
	conf.UseDBAppConfigs = true
	conf.DisableDashboardZeroConf = true
	conf.DBAppConfOptions.ConnectionString = srv.URL
	gw.SetConfig(conf)
	gw.SetNodeID("node-1")

	r := newIdPRegistry(gw)
	_, err := r.fetchFromDashboard()
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	// The raw response body of a failed auth attempt must not leak into the error
	// (and thus the logs).
	if strings.Contains(err.Error(), "nope") {
		t.Errorf("403 error must not include the raw response body: %v", err)
	}
}

// fetchJWKSKey must reject a non-HTTP(S) jwks_uri before building any client or
// issuing a request — guards against non-HTTP SSRF vectors (file://, gopher://).
func TestFetchJWKSKey_RejectsNonHTTPScheme(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	k := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	for _, url := range []string{"file:///etc/passwd", "gopher://127.0.0.1", "ftp://host/jwks"} {
		if got := k.fetchJWKSKey(url, "kid"); got != nil {
			t.Errorf("non-HTTP scheme %q must be rejected, got %v", url, got)
		}
	}
}

// doRefresh fetches and rebuilds end-to-end (RPC mode via injected loader).
func TestIdPRegistry_DoRefresh(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{"api-a": {}}}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	conf.SlaveOptions.RPCKey = "org-1"
	gw.SetConfig(conf)

	r := newIdPRegistry(gw)
	r.rpcLoaderFn = func() RPCDataLoader {
		return &fakeRPCLoader{payload: `[{"client_idp_id":"idp-1","issuer":"https://i1",` +
			`"api_mappings":{"api-a":{"scope_to_policy":{"read":"pol-read"}}}}]`}
	}

	if err := r.doRefresh(); err != nil {
		t.Fatalf("doRefresh error: %v", err)
	}
	b := r.BindingsForAPI("api-a")
	if len(b) != 1 || b[0].IdPID != "idp-1" || b[0].ScopeToPolicy["read"] != "pol-read" {
		t.Fatalf("registry not populated after doRefresh: %#v", b)
	}
}

// doRefresh is a no-op once the gateway context is cancelled (shutdown), so a
// debounced timer popping during shutdown cannot fetch.
func TestIdPRegistry_DoRefresh_ShutdownNoOp(t *testing.T) {
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	gw := &Gateway{apisByID: map[string]*APISpec{"api-a": {}}, ctx: cancelledCtx}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	gw.SetConfig(conf)

	called := false
	r := newIdPRegistry(gw)
	r.rpcLoaderFn = func() RPCDataLoader {
		called = true
		return &fakeRPCLoader{}
	}

	if err := r.doRefresh(); err != nil {
		t.Fatalf("doRefresh error: %v", err)
	}
	if called {
		t.Error("doRefresh must not fetch after context cancellation")
	}
}

// The matched binding travels via the request context (not the shared
// middleware struct), so per-request state cannot race across concurrent
// ProcessRequest calls.
func TestCtxMatchedBinding_Roundtrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	if got := ctxGetMatchedBinding(r); got != nil {
		t.Fatalf("empty request must have no matched binding, got %#v", got)
	}

	b := &Binding{IdPID: "idp-1", ScopeToPolicy: map[string]string{"read": "pol"}}
	ctxSetMatchedBinding(r, b)

	got := ctxGetMatchedBinding(r)
	if got == nil || got.IdPID != "idp-1" || got.ScopeToPolicy["read"] != "pol" {
		t.Fatalf("matched binding roundtrip failed: %#v", got)
	}
}

// In file mode (no DB, no RPC) fetch is deferred — returns no IdPs, no error.
func TestIdPRegistry_FetchFileMode(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	gw.SetConfig(config.Config{})

	r := newIdPRegistry(gw)
	idps, err := r.fetch()
	if err != nil {
		t.Fatalf("file mode fetch error: %v", err)
	}
	if idps != nil {
		t.Errorf("file mode must return no IdPs, got %#v", idps)
	}
}

// A registry-only OAS API has no JWT configuration in its OAS definition, so
// GetJWTConfiguration() returns nil. getScopeClaimNameOAS must not nil-deref
// when scope mapping comes from the registry rather than the OAS def.
func TestGetScopeClaimNameOAS_NilJWTConfig(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}, OAS: oas.OAS{}}
	k := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	got := k.getScopeClaimNameOAS(jwt.MapClaims{"scope": "read"})
	if got != "" {
		t.Fatalf("expected empty claim name for OAS API with no JWT config, got %q", got)
	}
}

// AC3: NoticeClientIdPChanged refreshes only the registry — it must be handled
// (so the registry refreshes) but must NOT trigger a router rebuild / API reload
// (the reloaded callback is never invoked).
func TestIdPRegistry_NoticeClientIdPChanged_NoReload(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	conf := ts.Gw.GetConfig()
	conf.AllowInsecureConfigs = true
	ts.Gw.SetConfig(conf)

	// Payload is the {org_id, client_idp_id} JSON contract; the direct-Dashboard
	// handler refreshes the whole registry, so it doesn't parse the payload.
	msg := testMessageAdapter{Msg: `{"Command": "ClientIdPChanged", "Payload": "{\"org_id\":\"org-1\",\"client_idp_id\":\"keycloak-prod\"}"}`}

	var handledCmd NotificationCommand
	handled := func(got NotificationCommand) { handledCmd = got }
	reloaded := func() { t.Fatal("ClientIdPChanged must NOT trigger an API reload") }

	ts.Gw.handleRedisEvent(&msg, handled, reloaded)

	if handledCmd != NoticeClientIdPChanged {
		t.Fatalf("want handled %q, got %q", NoticeClientIdPChanged, handledCmd)
	}
}

// AC1: a JWT API with no JWTSource/JWTJwksURIs but a registry binding resolves
// the signing key from the IdP's JWKS and maps the token scope to the bound
// policy — returning 200.
func TestIdPRegistry_JWT_ResolvesKeyAndScope(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "idp-reg-api"

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "idp-reg-policy"
		p.AccessRights = map[string]user.AccessDefinition{apiID: {APIName: "idp-reg-api"}}
		p.Partitions = user.PolicyPartitions{Acl: true}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = "" // registry-only: no manual JWKS source
		spec.JWTIdentityBaseField = "user_id"
		spec.Proxy.ListenPath = "/idp-reg/"
		spec.OrgID = "default"
	})

	// rebuild AFTER load so apisByID contains apiID (else the segment backstop
	// drops the binding).
	ts.Gw.idpRegistry.rebuild([]IdP{{
		ID:      "idp-1",
		Issuer:  "my-issuer",
		JWKSURI: testHttpJWK,
		APIMappings: map[string]ScopeMapping{
			apiID: {ScopeToPolicy: map[string]string{"read": pID}},
		},
	}})

	jwtToken := CreateJWKToken(func(tok *jwt.Token) {
		tok.Header["kid"] = "12345"
		tok.Claims.(jwt.MapClaims)["user_id"] = "user"
		tok.Claims.(jwt.MapClaims)["iss"] = "my-issuer"
		tok.Claims.(jwt.MapClaims)["scope"] = "read"
		tok.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(72 * time.Hour).Unix()
	})

	_, _ = ts.Run(t, test.TestCase{
		Path:    "/idp-reg/",
		Headers: map[string]string{"authorization": jwtToken},
		Code:    http.StatusOK,
	})
}

// AC2: setting a manual JWTSource on the same API bypasses the registry entirely
// (manual config wins — the probe never runs), still returning 200.
func TestIdPRegistry_JWT_ManualSourceWins(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "idp-reg-manual-api"

	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "idp-reg-manual-policy"
		p.AccessRights = map[string]user.AccessDefinition{apiID: {APIName: "idp-reg-manual-api"}}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.UseKeylessAccess = false
		spec.EnableJWT = true
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = testHttpJWK // manual JWKS source
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.Proxy.ListenPath = "/idp-reg-manual/"
		spec.OrgID = "default"
	})

	// A registry binding pointing at a BOGUS JWKS URL — if the probe ran it would
	// fail; manual must win so this is never consulted.
	ts.Gw.idpRegistry.rebuild([]IdP{{
		ID:      "idp-bogus",
		JWKSURI: "http://127.0.0.1:1/nope.json",
		APIMappings: map[string]ScopeMapping{
			apiID: {ScopeToPolicy: map[string]string{"read": "nonexistent-policy"}},
		},
	}})

	jwtToken := CreateJWKToken(func(tok *jwt.Token) {
		tok.Header["kid"] = "12345"
		tok.Claims.(jwt.MapClaims)["user_id"] = "user"
		tok.Claims.(jwt.MapClaims)["policy_id"] = pID
		tok.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(72 * time.Hour).Unix()
	})

	_, _ = ts.Run(t, test.TestCase{
		Path:    "/idp-reg-manual/",
		Headers: map[string]string{"authorization": jwtToken},
		Code:    http.StatusOK,
	})
}

// --- focused unit coverage for the non-RPC helpers ---

func newTestJWTMiddleware(apiID string) *JWTMiddleware {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	gw.SetConfig(config.Config{})
	gw.idpRegistry = newIdPRegistry(gw)
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: apiID}}
	return &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
}

func TestUnverifiedIssuerHint(t *testing.T) {
	withIss := &jwt.Token{Claims: jwt.MapClaims{ISS: "https://issuer"}}
	if got := unverifiedIssuerHint(withIss); got != "https://issuer" {
		t.Errorf("iss present: want https://issuer, got %q", got)
	}
	noIss := &jwt.Token{Claims: jwt.MapClaims{"sub": "x"}}
	if got := unverifiedIssuerHint(noIss); got != "" {
		t.Errorf("no iss claim: want empty, got %q", got)
	}
	notMap := &jwt.Token{Claims: jwt.RegisteredClaims{}}
	if got := unverifiedIssuerHint(notMap); got != "" {
		t.Errorf("non-MapClaims: want empty, got %q", got)
	}
}

func TestKeyFromJWKSet(t *testing.T) {
	if got := keyFromJWKSet(nil, "kid"); got != nil {
		t.Errorf("nil set must return nil, got %v", got)
	}
	if got := keyFromJWKSet(&jose.JSONWebKeySet{}, "kid"); got != nil {
		t.Errorf("set without kid must return nil, got %v", got)
	}
}

func TestCachedJWKSet(t *testing.T) {
	k := newTestJWTMiddleware("api-a")
	jwkCache := k.loadOrCreateJWKCache()

	if got := cachedJWKSet(jwkCache, "https://miss"); got != nil {
		t.Errorf("cache miss must return nil, got %v", got)
	}

	set := &jose.JSONWebKeySet{}
	jwkCache.Set("https://hit", set, cache.DefaultExpiration)
	if got := cachedJWKSet(jwkCache, "https://hit"); got != set {
		t.Errorf("cache hit must return the set, got %v", got)
	}

	jwkCache.Set("https://wrong", 1234, cache.DefaultExpiration)
	if got := cachedJWKSet(jwkCache, "https://wrong"); got != nil {
		t.Errorf("unexpected cache value type must return nil, got %v", got)
	}
}

func TestSecretFromIdPRegistry_EarlyReturns(t *testing.T) {
	tok := &jwt.Token{Header: map[string]interface{}{KID: "kid-1"}, Claims: jwt.MapClaims{}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Gw nil.
	kNoGw := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}}}}
	if got := kNoGw.secretFromIdPRegistry(r, tok); got != nil {
		t.Errorf("nil Gw must return nil, got %v", got)
	}

	// Gw set but registry nil.
	gw := &Gateway{}
	gw.SetConfig(config.Config{})
	kNoReg := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Spec: &APISpec{APIDefinition: &apidef.APIDefinition{}}, Gw: gw}}
	if got := kNoReg.secretFromIdPRegistry(r, tok); got != nil {
		t.Errorf("nil registry must return nil, got %v", got)
	}

	// Registry present but no bindings for this API.
	k := newTestJWTMiddleware("api-a")
	if got := k.secretFromIdPRegistry(r, tok); got != nil {
		t.Errorf("no bindings must return nil, got %v", got)
	}

	// Binding exists but the token has no kid.
	k.Gw.apisMu.Lock()
	k.Gw.apisByID["api-a"] = &APISpec{}
	k.Gw.apisMu.Unlock()
	k.Gw.idpRegistry.rebuild([]IdP{{
		ID: "idp-1", JWKSURI: "https://i1/jwks",
		APIMappings: map[string]ScopeMapping{"api-a": {}},
	}})
	noKid := &jwt.Token{Header: map[string]interface{}{}, Claims: jwt.MapClaims{}}
	if got := k.secretFromIdPRegistry(r, noKid); got != nil {
		t.Errorf("missing kid must return nil, got %v", got)
	}
}

func TestKeyForBinding_SkipBranches(t *testing.T) {
	k := newTestJWTMiddleware("api-a")
	k.Gw.idpRegistry.rebuild([]IdP{}) // empty registry

	// Unknown IdP id -> nil (no fetch).
	if got := k.keyForBinding(Binding{IdPID: "missing"}, "", "kid"); got != nil {
		t.Errorf("unknown IdP must return nil, got %v", got)
	}

	// Known IdP but issuer hint mismatches -> nil (no fetch).
	k.Gw.apisMu.Lock()
	k.Gw.apisByID["api-a"] = &APISpec{}
	k.Gw.apisMu.Unlock()
	k.Gw.idpRegistry.rebuild([]IdP{{
		ID: "idp-1", Issuer: "https://real", JWKSURI: "https://i1/jwks",
		APIMappings: map[string]ScopeMapping{"api-a": {}},
	}})
	if got := k.keyForBinding(Binding{IdPID: "idp-1"}, "https://other", "kid"); got != nil {
		t.Errorf("issuer mismatch must return nil, got %v", got)
	}
}

func TestUnmarshalIdPs_InvalidJSON(t *testing.T) {
	if _, err := unmarshalIdPs([]byte(`{not json`)); err == nil {
		t.Error("expected error for malformed envelope")
	}
	if _, err := unmarshalIdPs([]byte(`[not json`)); err == nil {
		t.Error("expected error for malformed array")
	}
}

func TestIdPRegistry_FetchFromDashboard_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	gw := &Gateway{apisByID: map[string]*APISpec{}, ctx: context.Background()}
	conf := config.Config{}
	conf.UseDBAppConfigs = true
	conf.DisableDashboardZeroConf = true
	conf.DBAppConfOptions.ConnectionString = srv.URL
	gw.SetConfig(conf)
	gw.SetNodeID("node-1")

	r := newIdPRegistry(gw)
	if _, err := r.fetchFromDashboard(); err == nil {
		t.Fatal("expected error on non-200 dashboard response")
	}
}

func TestFetchJWKSKey_CacheHit(t *testing.T) {
	k := newTestJWTMiddleware("api-a")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &priv.PublicKey, KeyID: "kid-1", Algorithm: "RS256", Use: "sig"},
	}}
	k.loadOrCreateJWKCache().Set("https://jwks", set, cache.DefaultExpiration)

	// Cache hit: returns the key without any network fetch.
	if k.fetchJWKSKey("https://jwks", "kid-1") == nil {
		t.Fatal("cache hit should return the key")
	}
}

// fetchFromRPC with the default loader (a real RPCStorageHandler) exercises the
// newIdPRegistry rpcLoaderFn closure; with the RPC client down it yields nil.
func TestIdPRegistry_FetchFromRPC_DefaultLoader(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	conf.SlaveOptions.RPCKey = "org"
	gw.SetConfig(conf)

	r := newIdPRegistry(gw) // default rpcLoaderFn
	idps, err := r.fetchFromRPC()
	if err != nil {
		t.Fatalf("fetchFromRPC error: %v", err)
	}
	if idps != nil {
		t.Errorf("RPC down should yield nil IdPs, got %#v", idps)
	}
}

// Refresh debounces and then rebuilds via doRefresh on the timer.
func TestIdPRegistry_Refresh_DebouncedRebuild(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{"api-a": {}}}
	conf := config.Config{}
	conf.SlaveOptions.UseRPC = true
	gw.SetConfig(conf)

	r := newIdPRegistry(gw)
	r.rpcLoaderFn = func() RPCDataLoader {
		return &fakeRPCLoader{payload: `[{"client_idp_id":"idp-1",` +
			`"api_mappings":{"api-a":{"scope_to_policy":{"read":"pol-read"}}}}]`}
	}

	r.Refresh()
	r.Refresh() // second call stops + reschedules the debounce timer

	var b []Binding
	for i := 0; i < 30; i++ {
		time.Sleep(20 * time.Millisecond)
		if b = r.BindingsForAPI("api-a"); len(b) > 0 {
			break
		}
	}
	if len(b) != 1 || b[0].IdPID != "idp-1" {
		t.Fatalf("Refresh did not rebuild the registry: %#v", b)
	}
}

// fetchJWKSKey returns nil when every fetch path fails (factory client, plain
// client, and the x5c legacy fallback) — covers the error + legacy branches.
func TestFetchJWKSKey_FetchError(t *testing.T) {
	k := newTestJWTMiddleware("api-a")
	if got := k.fetchJWKSKey("http://127.0.0.1:1/jwks", "kid-1"); got != nil {
		t.Errorf("unreachable JWKS must return nil, got %v", got)
	}
}

// The client-IdP registry is backed up to Redis on RPC sync and restored from
// that backup in emergency mode, mirroring API/policy recovery.
func TestIdPRegistry_RPCBackup(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const payload = `[{"client_idp_id":"idp-1","issuer":"https://i1",` +
		`"api_mappings":{"api-a":{"scope_to_policy":{"read":"pol-read"}}}}]`

	t.Run("save then load round-trips", func(t *testing.T) {
		if err := ts.Gw.saveRPCIdPsBackup(payload); err != nil {
			t.Fatalf("saveRPCIdPsBackup: %v", err)
		}
		idps, err := ts.Gw.LoadIdPsFromRPCBackup()
		if err != nil {
			t.Fatalf("LoadIdPsFromRPCBackup: %v", err)
		}
		if len(idps) != 1 || idps[0].ID != "idp-1" {
			t.Fatalf("backup round-trip wrong: %#v", idps)
		}
		if idps[0].APIMappings["api-a"].ScopeToPolicy["read"] != "pol-read" {
			t.Errorf("mappings lost in backup: %#v", idps[0].APIMappings)
		}
	})

	t.Run("malformed payload is not stored", func(t *testing.T) {
		if err := ts.Gw.saveRPCIdPsBackup("{not json"); err == nil {
			t.Error("expected error for malformed backup payload")
		}
	})
}

// In emergency mode fetchFromRPC restores the registry from the Redis backup
// instead of calling MDCB.
func TestIdPRegistry_FetchFromRPC_EmergencyMode(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const payload = `[{"client_idp_id":"idp-1",` +
		`"api_mappings":{"api-a":{"scope_to_policy":{"read":"pol-read"}}}}]`
	if err := ts.Gw.saveRPCIdPsBackup(payload); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	rpc.SetEmergencyMode(t, true)
	defer rpc.SetEmergencyMode(t, false)

	r := newIdPRegistry(ts.Gw)
	idps, err := r.fetchFromRPC()
	if err != nil {
		t.Fatalf("fetchFromRPC (emergency): %v", err)
	}
	if len(idps) != 1 || idps[0].ID != "idp-1" {
		t.Fatalf("emergency mode must load from backup, got %#v", idps)
	}
}
