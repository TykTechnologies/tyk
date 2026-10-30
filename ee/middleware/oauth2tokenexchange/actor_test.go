//go:build ee || dev

package oauth2tokenexchange

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

func boolPtr(b bool) *bool { return &b }

func newTestMiddleware() *Middleware {
	return &Middleware{actorCache: newActorTokenCache()}
}

func TestAcquireActorToken_NoActorBlock_Impersonation(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	tok, id, err := m.acquireActorToken(r, &oas.OAuth2TokenExchangeProvider{})
	require.NoError(t, err)
	assert.Empty(t, tok)
	assert.Equal(t, oas.OAuth2ActorImpersonation, id, "no actor block must signal impersonation")
}

func TestAcquireActorToken_Static_ReturnsTokenAndID(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{
			Source: oas.OAuth2ActorSourceStatic,
			Static: &oas.OAuth2ActorStatic{Token: "static-actor-token"},
		},
	}

	tok, id, err := m.acquireActorToken(r, provider)
	require.NoError(t, err)
	assert.Equal(t, "static-actor-token", tok)
	assert.Equal(t, oauth2common.HashActorID("static-actor-token"), id)
	assert.NotEqual(t, oas.OAuth2ActorImpersonation, id, "delegation actorID must differ from impersonation")
}

func TestAcquireActorToken_Static_EmptyTokenErrors(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceStatic, Static: &oas.OAuth2ActorStatic{}},
	}

	_, _, err := m.acquireActorToken(r, provider)
	require.Error(t, err)
}

func TestAcquireActorToken_Header_StripsByDefault(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(DefaultActorTokenHeader, "header-actor-token")
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader},
	}

	tok, id, err := m.acquireActorToken(r, provider)
	require.NoError(t, err)
	assert.Equal(t, "header-actor-token", tok)
	assert.Equal(t, oauth2common.HashActorID("header-actor-token"), id)
	assert.Empty(t, r.Header.Get(DefaultActorTokenHeader), "actor header must be stripped from the proxied request by default")
}

func TestAcquireActorToken_Header_NoStripWhenDisabled(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Custom-Actor", "tok")
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{
			Source: oas.OAuth2ActorSourceHeader,
			Header: &oas.OAuth2ActorHeader{Name: "X-Custom-Actor", Strip: boolPtr(false)},
		},
	}

	_, _, err := m.acquireActorToken(r, provider)
	require.NoError(t, err)
	assert.Equal(t, "tok", r.Header.Get("X-Custom-Actor"), "strip:false must leave the header intact")
}

func TestAcquireActorToken_Header_RequiredButAbsentErrors(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader},
	}

	_, _, err := m.acquireActorToken(r, provider)
	require.Error(t, err, "required header (default) absent must error, not silently impersonate")
}

func TestAcquireActorToken_Header_NotRequiredFallsBackToImpersonation(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{
			Source: oas.OAuth2ActorSourceHeader,
			Header: &oas.OAuth2ActorHeader{Required: boolPtr(false)},
		},
	}

	tok, id, err := m.acquireActorToken(r, provider)
	require.NoError(t, err)
	assert.Empty(t, tok)
	assert.Equal(t, oas.OAuth2ActorImpersonation, id, "required:false absent header falls back to impersonation")
}

func TestAcquireActorToken_CC_MissingBlockErrors(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceClientCredentials},
	}

	_, _, err := m.acquireActorToken(r, provider)
	require.Error(t, err)
}

func TestGetOrAcquireActorTokenViaCC_FetchesCachesAndReuses(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		assert.Equal(t, oas.OAuth2GrantTypeClientCredentials, r.Form.Get(oas.OAuth2FormGrantType))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"cc-actor-tok","expires_in":3600}`))
	}))
	defer srv.Close()

	m := newTestMiddleware()
	cc := &oas.OAuth2ActorClientCredentials{
		TokenEndpoint: srv.URL,
		ClientID:      "tyk-gateway-actor",
		ClientSecret:  "secret",
		Scopes:        []string{"agent"},
	}

	tok1, err := m.getOrAcquireActorTokenViaCC(httptest.NewRequest(http.MethodGet, "/", nil).Context(), cc, 0, "")
	require.NoError(t, err)
	assert.Equal(t, "cc-actor-tok", tok1)

	tok2, err := m.getOrAcquireActorTokenViaCC(httptest.NewRequest(http.MethodGet, "/", nil).Context(), cc, 0, "")
	require.NoError(t, err)
	assert.Equal(t, "cc-actor-tok", tok2)
	assert.Equal(t, 1, calls, "second acquisition must be served from cache, not a second IdP call")
}

func TestGetOrAcquireActorTokenViaCC_IdPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer srv.Close()

	m := newTestMiddleware()
	cc := &oas.OAuth2ActorClientCredentials{TokenEndpoint: srv.URL, ClientID: "actor"}

	_, err := m.getOrAcquireActorTokenViaCC(httptest.NewRequest(http.MethodGet, "/", nil).Context(), cc, 0, "")
	require.Error(t, err)
}
