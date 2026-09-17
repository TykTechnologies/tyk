package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

var testJWKSKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func testJWKSBody(t *testing.T, kids ...string) []byte {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for _, kid := range kids {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &testJWKSKey().PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
	}
	body, err := json.Marshal(set)
	require.NoError(t, err)
	return body
}

// jwksTestServer counts fetches. With block set, each request waits until
// release is closed.
type jwksTestServer struct {
	*httptest.Server
	fetches atomic.Int32
	status  atomic.Int32
	body    atomic.Pointer[[]byte]
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *jwksTestServer) unblock() { s.once.Do(func() { close(s.release) }) }

func newJWKSTestServer(t *testing.T, body []byte, block bool) *jwksTestServer {
	t.Helper()
	s := &jwksTestServer{started: make(chan struct{}, 16)}
	s.body.Store(&body)
	if block {
		s.release = make(chan struct{})
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		select {
		case s.started <- struct{}{}:
		default:
		}
		if s.release != nil {
			<-s.release
		}
		if code := s.status.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		_, _ = w.Write(*s.body.Load())
	}))
	t.Cleanup(s.Close)
	if block {
		t.Cleanup(s.unblock)
	}
	return s
}

func newTestJWKSRegistry(apiIDs ...string) *IdPRegistry {
	gw := &Gateway{apisByID: loadedAPIs(apiIDs...)}
	gw.SetConfig(config.Config{})
	return newIdPRegistry(gw)
}

func TestIdPJWKSTTL(t *testing.T) {
	for _, tc := range []struct {
		value     string
		gwDefault time.Duration
		ttl       time.Duration
		source    ttlSource
		err       bool
	}{
		{"", 240 * time.Second, 240 * time.Second, ttlFromDefault, false},
		{"2m30s", 240 * time.Second, 150 * time.Second, ttlFromRecord, false},
		{"5s", 240 * time.Second, jwksMinTTL, ttlFromFloor, false},
		{"abc", 240 * time.Second, 240 * time.Second, ttlFromDefault, true},
		{"-5s", 240 * time.Second, 240 * time.Second, ttlFromDefault, true},
		{"", 5 * time.Second, jwksMinTTL, ttlFromFloor, false},
	} {
		t.Run(tc.value+"/"+tc.gwDefault.String(), func(t *testing.T) {
			ttl, source, err := IdP{JWKSCacheTimeout: tc.value}.jwksTTL(tc.gwDefault)
			assert.Equal(t, tc.ttl, ttl)
			assert.Equal(t, tc.source, source)
			assert.Equal(t, tc.err, err != nil)
		})
	}
	assert.Equal(t, 240*time.Second, jwksDefaultTTL(config.Config{}))
}

func TestIdPRegistry_JWKSEntriesAcrossRebuilds(t *testing.T) {
	r := newTestJWKSRegistry("api-a", "api-b")
	rec := IdP{ID: "idp-1", JWKSURI: "https://i1/jwks", JWKSCacheTimeout: "1m",
		APIMappings: map[string]ScopeMapping{"api-a": {}, "api-b": {}}}
	entryOf := func(apiID string) *jwksEntry { return r.BindingsForAPI(apiID)[0].JWKS }

	r.rebuild([]IdP{rec})
	first := entryOf("api-a")
	require.NotNil(t, first)
	assert.Same(t, first, entryOf("api-b"), "one entry per record")
	assert.Equal(t, time.Minute, first.ttl)

	r.rebuild([]IdP{rec})
	assert.Same(t, first, entryOf("api-a"), "unchanged record keeps its entry")

	rec.JWKSCacheTimeout = "2m"
	r.rebuild([]IdP{rec})
	assert.NotSame(t, first, entryOf("api-a"), "changed TTL gets a new entry")

	rec.JWKSURI = "https://i1/other"
	second := entryOf("api-a")
	r.rebuild([]IdP{rec})
	assert.NotSame(t, second, entryOf("api-a"), "changed URL gets a new entry")

	rec.JWKSURI = "file:///etc/passwd"
	r.rebuild([]IdP{rec})
	assert.Nil(t, entryOf("api-a"), "non-HTTP jwks_uri gets no entry")

	r.rebuild(nil)
	assert.Empty(t, r.jwksByIdP)
}

func TestIdPRegistry_SameIDInTwoOrgsHasSeparateEntries(t *testing.T) {
	gw := &Gateway{apisByID: map[string]*APISpec{
		"api-a": loadedAPI("api-a"), "api-b": loadedAPI("api-b"),
	}}
	gw.apisByID["api-a"].OrgID, gw.apisByID["api-b"].OrgID = "org-a", "org-b"
	gw.SetConfig(config.Config{})
	r := newIdPRegistry(gw)
	r.rebuild([]IdP{
		{ID: "shared", OrgID: "org-a", JWKSURI: "https://a/jwks", APIMappings: map[string]ScopeMapping{"api-a": {}}},
		{ID: "shared", OrgID: "org-b", JWKSURI: "https://a/jwks", APIMappings: map[string]ScopeMapping{"api-b": {}}},
	})
	assert.NotSame(t, r.BindingsForAPI("api-a")[0].JWKS, r.BindingsForAPI("api-b")[0].JWKS)
}

func TestJWKSEntry_TwoAPIsShareOneFetch(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), false)
	r := newTestJWKSRegistry("api-a", "api-b")
	r.rebuild([]IdP{{ID: "idp-1", JWKSURI: srv.URL, APIMappings: map[string]ScopeMapping{"api-a": {}, "api-b": {}}}})

	ctx := context.Background()
	for _, apiID := range []string{"api-a", "api-b", "api-a"} {
		assert.NotNil(t, r.BindingsForAPI(apiID)[0].JWKS.key(ctx, r.fetcher, "kid-1"))
	}
	assert.Equal(t, int32(1), srv.fetches.Load())
}

// A record edited while a fetch is in flight must not be served the key set
// that fetch returns: the edit replaces the entry, and the late result lands on
// the orphaned one.
func TestJWKSEntry_EditDuringFetchIsNotServed(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), true)
	r := newTestJWKSRegistry("api-a")
	rec := IdP{ID: "idp-1", JWKSURI: srv.URL, JWKSCacheTimeout: "10m", APIMappings: map[string]ScopeMapping{"api-a": {}}}
	r.rebuild([]IdP{rec})
	old := r.BindingsForAPI("api-a")[0].JWKS

	done := make(chan struct{})
	go func() {
		defer close(done)
		old.key(context.Background(), r.fetcher, "kid-1")
	}()
	<-srv.started

	rec.JWKSCacheTimeout = "10s"
	r.rebuild([]IdP{rec})
	srv.unblock()
	<-done

	current := r.BindingsForAPI("api-a")[0].JWKS
	require.NotSame(t, old, current)
	assert.Nil(t, current.cached.Load(), "the new entry must not hold the in-flight result")
	assert.NotNil(t, old.cached.Load())
}

func TestJWKSEntry_FlushDuringFetchIsNotStored(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), true)
	e := newJWKSEntry(srv.URL, time.Minute)
	f := newTestJWKSRegistry().fetcher

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.key(context.Background(), f, "kid-1")
	}()
	<-srv.started
	e.flush()
	srv.unblock()
	<-done

	assert.Nil(t, e.cached.Load())
}

func TestJWKSEntry_UnknownKidCooldown(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), false)
	e := newJWKSEntry(srv.URL, time.Hour)
	f := newTestJWKSRegistry().fetcher
	ctx := context.Background()

	require.NotNil(t, e.key(ctx, f, "kid-1"))
	assert.Nil(t, e.key(ctx, f, "kid-2"))
	assert.Equal(t, int32(1), srv.fetches.Load(), "an unknown kid inside the cooldown must not fetch")

	body := testJWKSBody(t, "kid-1", "kid-2")
	srv.body.Store(&body)
	e.lastSuccess.Store(time.Now().Add(-jwksKidMissCooldown).UnixNano())
	assert.NotNil(t, e.key(ctx, f, "kid-2"), "after the cooldown an unknown kid re-fetches")
	assert.Equal(t, int32(2), srv.fetches.Load())
}

func TestJWKSEntry_FailureBackoff(t *testing.T) {
	srv := newJWKSTestServer(t, nil, false)
	srv.status.Store(http.StatusServiceUnavailable)
	e := newJWKSEntry(srv.URL, time.Minute)
	f := newTestJWKSRegistry().fetcher
	ctx := context.Background()

	assert.Nil(t, e.key(ctx, f, "kid-1"))
	assert.Nil(t, e.key(ctx, f, "kid-1"))
	assert.Equal(t, int32(1), srv.fetches.Load(), "requests inside the backoff must not fetch")

	e.mu.Lock()
	wait := time.Until(e.retryAfter)
	e.retryAfter = time.Time{}
	e.mu.Unlock()
	assert.InDelta(t, time.Second, wait, float64(600*time.Millisecond), "first wait is 1 s with jitter")

	assert.Nil(t, e.key(ctx, f, "kid-1"))
	assert.Equal(t, int32(2), srv.fetches.Load())

	srv.status.Store(0)
	body := testJWKSBody(t, "kid-1")
	srv.body.Store(&body)
	e.mu.Lock()
	e.retryAfter = time.Time{}
	e.mu.Unlock()
	assert.NotNil(t, e.key(ctx, f, "kid-1"))
	e.mu.Lock()
	defer e.mu.Unlock()
	assert.True(t, e.retryAfter.IsZero(), "success clears the backoff")
}

func TestJWKSEntry_WaiterLeavesOnContextCancel(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), true)
	e := newJWKSEntry(srv.URL, time.Minute)
	f := newTestJWKSRegistry().fetcher

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan any, 1)
	go func() { got <- e.key(ctx, f, "kid-1") }()
	<-srv.started
	cancel()

	select {
	case key := <-got:
		assert.Nil(t, key)
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not leave after its context was cancelled")
	}

	srv.unblock()
	require.Eventually(t, func() bool { return e.cached.Load() != nil }, 5*time.Second, 10*time.Millisecond,
		"the fetch completes and stores for later requests")
}

func TestJWKSFetcher_LegacyX5c(t *testing.T) {
	srv := newJWKSTestServer(t, []byte(jwkTestJsonLegacy), false)
	f := newTestJWKSRegistry().fetcher

	keys, outcome, err := f.get(srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "legacy", outcome)
	assert.NotNil(t, keys["12345"])
	assert.Equal(t, int32(1), srv.fetches.Load())
}

func TestJWKSFetcher_BodyCap(t *testing.T) {
	srv := newJWKSTestServer(t, []byte(strings.Repeat(" ", jwksMaxBodyBytes+1)), false)
	_, _, err := newTestJWKSRegistry().fetcher.get(srv.URL)
	assert.ErrorContains(t, err, "exceeds")
}

func seedJWKS(entries ...*jwksEntry) {
	for _, e := range entries {
		e.cached.Store(&cachedJWKS{keys: map[string]any{}, expires: time.Now().Add(time.Hour)})
	}
}

func cachedJWKSEntry(e *jwksEntry) bool { return e.cached.Load() != nil }

// The per-API JWKS routes and the client IdP routes act on separate caches.
func TestClientIdPJWKSFlushRoutes(t *testing.T) {
	r := newTestJWKSRegistry("api-a", "api-b")
	gw := r.gw
	gw.idpRegistry = r
	gw.apisByID["api-a"].OrgID, gw.apisByID["api-b"].OrgID = "org-1", "org-1"
	r.rebuild([]IdP{
		{ID: "idp-a", OrgID: "org-1", JWKSURI: "https://a/jwks", APIMappings: map[string]ScopeMapping{"api-a": {}}},
		{ID: "idp-b", OrgID: "org-1", JWKSURI: "https://b/jwks", APIMappings: map[string]ScopeMapping{"api-b": {}}},
	})
	a, b := r.BindingsForAPI("api-a")[0].JWKS, r.BindingsForAPI("api-b")[0].JWKS

	t.Run("per-API routes leave client IdP entries alone", func(t *testing.T) {
		seedJWKS(a, b)
		gw.invalidateJWKSCacheByAPIID("api-a")
		gw.invalidateJWKSCacheForAllAPIs(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/tyk/cache/jwks", nil))
		assert.True(t, cachedJWKSEntry(a))
		assert.True(t, cachedJWKSEntry(b))
	})

	t.Run("one record", func(t *testing.T) {
		seedJWKS(a, b)
		rec := httptest.NewRecorder()
		req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/tyk/clientidps/org-1/idp-a/jwks-cache", nil),
			map[string]string{"orgID": "org-1", "idpID": "idp-a"})
		gw.invalidateClientIdPJWKSCache(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.False(t, cachedJWKSEntry(a))
		assert.True(t, cachedJWKSEntry(b))
	})

	t.Run("all records", func(t *testing.T) {
		seedJWKS(a, b)
		gw.invalidateAllClientIdPJWKSCaches(httptest.NewRecorder(), httptest.NewRequest(http.MethodDelete, "/tyk/clientidps/jwks-cache", nil))
		assert.False(t, cachedJWKSEntry(a))
		assert.False(t, cachedJWKSEntry(b))
	})
}

func TestClientIdPJWKSFlush_ClusterSignals(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "idp-flush-api"
		spec.OrgID = "org-1"
		spec.Proxy.ListenPath = "/idp-flush/"
	})
	// The id contains ':' because client_idp_id is caller-supplied and keyspace
	// events are ':'-separated.
	ts.Gw.idpRegistry.rebuild([]IdP{{ID: "idp:1", OrgID: "org-1", JWKSURI: "https://a/jwks",
		APIMappings: map[string]ScopeMapping{"idp-flush-api": {}}}})
	e := ts.Gw.idpRegistry.BindingsForAPI("idp-flush-api")[0].JWKS
	flushed := func() bool { return !cachedJWKSEntry(e) }

	t.Run("redis notification", func(t *testing.T) {
		seedJWKS(e)
		ts.Gw.MainNotifier.Notify(Notification{
			Command: NoticeInvalidateJWKSCacheForClientIdP,
			Payload: `{"org_id":"org-1","client_idp_id":"idp:1"}`,
			Gw:      ts.Gw,
		})
		require.Eventually(t, flushed, 5*time.Second, 50*time.Millisecond)
	})

	t.Run("RPC keyspace event", func(t *testing.T) {
		seedJWKS(e)
		rpc := RPCStorageHandler{KeyPrefix: "rpc.listener.", SuppressRegister: true, Gw: ts.Gw}
		rpc.ProcessKeySpaceChanges([]string{"idp:1:" + NoticeInvalidateJWKSCacheForClientIdP.String()}, "org-1")
		require.Eventually(t, flushed, 5*time.Second, 50*time.Millisecond)
	})
}

// Rebuilds, lookups, fetches and flushes running together. The assertions are
// weak on purpose: the test exists to be run with -race.
func TestIdPRegistry_ConcurrentUse(t *testing.T) {
	srv := newJWKSTestServer(t, testJWKSBody(t, "kid-1"), false)
	r := newTestJWKSRegistry("api-a", "api-b")
	r.gw.idpRegistry = r
	records := func(ttl string) []IdP {
		return []IdP{{ID: "idp-1", JWKSURI: srv.URL, JWKSCacheTimeout: ttl,
			APIMappings: map[string]ScopeMapping{"api-a": {}, "api-b": {}}}}
	}
	r.rebuild(records("1m"))
	k := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Gw: r.gw, Spec: loadedAPI("api-a")}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	loop := func(step func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				step()
			}
		}()
	}

	var n atomic.Int32
	loop(func() {
		ttl := []string{"1m", "2m"}[n.Add(1)%2]
		r.refreshMu.Lock()
		r.rebuild(records(ttl))
		r.refreshMu.Unlock()
		time.Sleep(time.Millisecond)
	})
	for i := 0; i < 4; i++ {
		loop(func() {
			for _, api := range []string{"api-a", "api-b"} {
				for _, b := range r.BindingsForAPI(api) {
					k.keyForBinding(req, b, "", "kid-1")
					k.keyForBinding(req, b, "", "kid-unknown")
				}
			}
		})
	}
	loop(func() { r.flushAllJWKS(); time.Sleep(time.Millisecond) })
	loop(func() { r.flushJWKS(idpKey{"", "idp-1"}); time.Sleep(time.Millisecond) })
	wg.Wait()

	assert.NotNil(t, k.keyForBinding(req, r.BindingsForAPI("api-a")[0], "", "kid-1"))
}

func BenchmarkJWKSRegistryKeyHit(b *testing.B) {
	r := newTestJWKSRegistry("api-a")
	r.gw.idpRegistry = r
	r.rebuild([]IdP{{ID: "idp-1", JWKSURI: "https://i1/jwks", APIMappings: map[string]ScopeMapping{"api-a": {}}}})
	binding := r.BindingsForAPI("api-a")[0]
	binding.JWKS.cached.Store(&cachedJWKS{keys: map[string]any{"kid-1": &testJWKSKey().PublicKey}, expires: time.Now().Add(time.Hour)})
	k := &JWTMiddleware{BaseMiddleware: &BaseMiddleware{Gw: r.gw, Spec: loadedAPI("api-a")}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, bd := range r.BindingsForAPI("api-a") {
				if k.keyForBinding(req, bd, "", "kid-1") == nil {
					b.Fatal("expected a key")
				}
			}
		}
	})
}
