//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// actorIdPStub serves client_credentials responses that name the secret they
// were minted with, so a test can tell whose credentials produced a token.
// hold delays each response so a concurrent caller has time to join an
// in-flight acquisition.
func actorIdPStub(t *testing.T, hold time.Duration) (srv *httptest.Server, secretsSeen func() map[string]int, calls func() int32) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]int{}
	var n int32

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		_, secret, _ := r.BasicAuth()
		mu.Lock()
		seen[secret]++
		mu.Unlock()
		if hold > 0 {
			time.Sleep(hold)
		}
		fmt.Fprintf(w, `{"access_token":"token-for-%s","expires_in":3600}`, secret)
	}))
	t.Cleanup(srv.Close)

	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range seen {
			out[k] = v
		}
		return out
	}, func() int32 { return atomic.LoadInt32(&n) }
}

// TestActorTokenIsolatedPerCredentials asserts that two APIs sharing a token
// endpoint, client id and scopes but holding DIFFERENT client secrets never
// share an actor token. Before the per-middleware singleflight group and the
// secret-bound cache key, a concurrent second request joined the first API's
// in-flight acquisition and was served a token minted with the other API's
// secret — its own credentials never reaching the IdP.
func TestActorTokenIsolatedPerCredentials(t *testing.T) {
	srv, secretsSeen, calls := actorIdPStub(t, 300*time.Millisecond)

	ccFor := func(secret string) *oas.OAuth2ActorClientCredentials {
		return &oas.OAuth2ActorClientCredentials{
			TokenEndpoint: srv.URL,
			ClientID:      "shared-client-id",
			ClientSecret:  secret,
			Scopes:        []string{"scope-a"},
		}
	}

	// Separate Middleware instances: the gateway builds one per API spec.
	apiA := &Middleware{actorCache: newActorTokenCache()}
	apiB := &Middleware{actorCache: newActorTokenCache()}

	var tokA, tokB string
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tokA, errA = apiA.getOrAcquireActorTokenViaCC(context.Background(), ccFor("secret-a"), 0, "provA")
	}()
	// Let A reach the IdP first so B would join its in-flight call.
	time.Sleep(50 * time.Millisecond)
	go func() {
		defer wg.Done()
		tokB, errB = apiB.getOrAcquireActorTokenViaCC(context.Background(), ccFor("secret-b"), 0, "provB")
	}()
	wg.Wait()

	require.NoError(t, errA)
	require.NoError(t, errB)
	assert.Equal(t, "token-for-secret-a", tokA, "API A must get the token minted with its own secret")
	assert.Equal(t, "token-for-secret-b", tokB, "API B must get the token minted with its own secret")
	assert.NotEqual(t, tokA, tokB, "APIs with different secrets must not share an actor token")

	// Both APIs must have actually authenticated with their own credentials.
	seen := secretsSeen()
	assert.Equal(t, 1, seen["secret-a"], "API A's secret must reach the IdP")
	assert.Equal(t, 1, seen["secret-b"], "API B's secret must reach the IdP")
	assert.Equal(t, int32(2), calls(), "each distinct credential set needs its own IdP round-trip")
}

// TestActorTokenIsolatedPerCredentialsSameMiddleware covers two providers on a
// SINGLE middleware sharing endpoint+clientId with different secrets: scoping
// the singleflight group per middleware alone does not separate these, so the
// cache key must bind the secret too.
func TestActorTokenIsolatedPerCredentialsSameMiddleware(t *testing.T) {
	srv, secretsSeen, _ := actorIdPStub(t, 0)

	mw := &Middleware{actorCache: newActorTokenCache()}
	ccFor := func(secret string) *oas.OAuth2ActorClientCredentials {
		return &oas.OAuth2ActorClientCredentials{
			TokenEndpoint: srv.URL,
			ClientID:      "shared-client-id",
			ClientSecret:  secret,
			Scopes:        []string{"scope-a"},
		}
	}

	tok1, err := mw.getOrAcquireActorTokenViaCC(context.Background(), ccFor("secret-1"), 0, "p1")
	require.NoError(t, err)
	tok2, err := mw.getOrAcquireActorTokenViaCC(context.Background(), ccFor("secret-2"), 0, "p2")
	require.NoError(t, err)

	assert.Equal(t, "token-for-secret-1", tok1)
	assert.Equal(t, "token-for-secret-2", tok2)
	seen := secretsSeen()
	assert.Equal(t, 1, seen["secret-1"])
	assert.Equal(t, 1, seen["secret-2"])
}

// TestActorTokenCachedForSameCredentials guards the cache still works: the same
// credentials must be served from cache without a second IdP round-trip.
func TestActorTokenCachedForSameCredentials(t *testing.T) {
	srv, _, calls := actorIdPStub(t, 0)

	mw := &Middleware{actorCache: newActorTokenCache()}
	cc := &oas.OAuth2ActorClientCredentials{
		TokenEndpoint: srv.URL,
		ClientID:      "cid",
		ClientSecret:  "s",
		Scopes:        []string{"scope-a"},
	}

	tok1, err := mw.getOrAcquireActorTokenViaCC(context.Background(), cc, 0, "p")
	require.NoError(t, err)
	tok2, err := mw.getOrAcquireActorTokenViaCC(context.Background(), cc, 0, "p")
	require.NoError(t, err)

	assert.Equal(t, tok1, tok2)
	assert.Equal(t, int32(1), calls(), "identical credentials must be served from the actor cache")
}

// TestActorTokenConcurrentSameCredentialsCoalesced guards that singleflight
// still coalesces concurrent first-misses for identical credentials.
func TestActorTokenConcurrentSameCredentialsCoalesced(t *testing.T) {
	srv, _, calls := actorIdPStub(t, 200*time.Millisecond)

	mw := &Middleware{actorCache: newActorTokenCache()}
	cc := &oas.OAuth2ActorClientCredentials{
		TokenEndpoint: srv.URL, ClientID: "cid", ClientSecret: "s", Scopes: []string{"a"},
	}

	const n = 8
	toks := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := mw.getOrAcquireActorTokenViaCC(context.Background(), cc, 0, "p")
			assert.NoError(t, err)
			toks[i] = tok
		}(i)
	}
	wg.Wait()

	for i := range toks {
		assert.Equal(t, "token-for-s", toks[i])
	}
	assert.Equal(t, int32(1), calls(), "concurrent misses for identical credentials must coalesce into one IdP call")
}
