//go:build ee || dev

package oauth2tokenexchange

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// TestFetchExchangedToken_EndpointPlaceholder pins per-request tokenEndpoint
// resolution from the inbound token's claims: the claim value lands in the
// endpoint path, and a token lacking the claim is rejected before any IdP call.
func TestFetchExchangedToken_EndpointPlaceholder(t *testing.T) {
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}

	newIdP := func(t *testing.T) (*httptest.Server, *[]string) {
		t.Helper()
		var paths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"exchanged","expires_in":300}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &paths
	}

	newProvider := func(endpoint string) *oas.OAuth2TokenExchangeProvider {
		return &oas.OAuth2TokenExchangeProvider{
			Name:          "corp-idp",
			GrantType:     oas.OAuth2ProviderGrantJWTBearer,
			TokenEndpoint: endpoint,
			ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "cid", ClientSecret: "s"},
		}
	}

	t.Run("claim value selects the per-tenant endpoint", func(t *testing.T) {
		idp, paths := newIdP(t)
		provider := newProvider(idp.URL + "/{claim.tid}/token")

		for _, tid := range []string{"aaa-111", "bbb-222"} {
			st := &oauth2common.State{Claims: jwt.MapClaims{"tid": tid}, RawToken: "inbound"}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			_, _, err := mwWithoutTykOps().fetchExchangedToken(r, st, provider, target)
			require.NoError(t, err)
		}
		assert.Equal(t, []string{"/aaa-111/token", "/bbb-222/token"}, *paths)
	})

	t.Run("token lacking the claim is rejected before any IdP call", func(t *testing.T) {
		idp, paths := newIdP(t)
		provider := newProvider(idp.URL + "/{claim.tid}/token")

		st := &oauth2common.State{Claims: jwt.MapClaims{}, RawToken: "inbound"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := mwWithoutTykOps().fetchExchangedToken(r, st, provider, target)
		require.Error(t, err)
		assert.Empty(t, *paths, "the IdP must record zero calls")
	})

	t.Run("claim value failing the charset guard is rejected before any IdP call", func(t *testing.T) {
		idp, paths := newIdP(t)
		provider := newProvider(idp.URL + "/{claim.tid}/token")

		st := &oauth2common.State{Claims: jwt.MapClaims{"tid": "../evil"}, RawToken: "inbound"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := mwWithoutTykOps().fetchExchangedToken(r, st, provider, target)
		require.Error(t, err)
		assert.Empty(t, *paths, "the IdP must record zero calls")
	})
}

// TestFetchExchangedToken_EndpointPlaceholder_CacheIsPerTenant pins that a
// cached exchanged token is never served across tenants: two tokens identical
// but for the endpoint-selecting claim must each hit their own tenant endpoint.
func TestFetchExchangedToken_EndpointPlaceholder_CacheIsPerTenant(t *testing.T) {
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}

	var paths []string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged","expires_in":300}`))
	}))
	t.Cleanup(idp.Close)

	provider := &oas.OAuth2TokenExchangeProvider{
		Name:          "corp-idp",
		GrantType:     oas.OAuth2ProviderGrantJWTBearer,
		TokenEndpoint: idp.URL + "/{claim.tid}/token",
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "cid", ClientSecret: "s"},
		Cache:         &oas.OAuth2ExchangeCache{Enabled: true},
	}

	m := &Middleware{Base: newFakeBase(), Spec: model.MergedAPI{OAS: &oas.OAS{}}}
	m.Cache = newSingleFlightCache(&fakeCache{items: map[string]string{}})

	// Same issuer and subject — only the endpoint-selecting claim differs.
	for _, tid := range []string{"tenant-a", "tenant-b"} {
		st := &oauth2common.State{
			Claims:   jwt.MapClaims{"iss": "https://one-issuer", "sub": "user-1", "tid": tid},
			RawToken: "inbound",
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := m.fetchExchangedToken(r, st, provider, target)
		require.NoError(t, err)
	}

	assert.Equal(t, []string{"/tenant-a/token", "/tenant-b/token"}, paths,
		"a token cached for one tenant endpoint must not be served for another")
}
