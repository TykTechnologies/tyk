//go:build ee || dev

package oauth2tokenexchange

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// replaceVarsWith stands in for the gateway's ReplaceTykVariables hook.
func replaceVarsWith(tid string) func(string) string {
	return func(in string) string {
		return strings.ReplaceAll(in, "$tyk_context.jwt_claims_tid", tid)
	}
}

// TestFetchExchangedToken_EndpointVariables pins per-request tokenEndpoint
// resolution through the State's variable-replacement hook.
func TestFetchExchangedToken_EndpointVariables(t *testing.T) {
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

	t.Run("replaced variable selects the per-tenant endpoint", func(t *testing.T) {
		idp, paths := newIdP(t)
		provider := newProvider(idp.URL + "/$tyk_context.jwt_claims_tid/token")

		for _, tid := range []string{"aaa-111", "bbb-222"} {
			st := &oauth2common.State{ReplaceVariables: replaceVarsWith(tid), RawToken: "inbound"}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			_, _, err := mwWithoutTykOps().fetchExchangedToken(r, st, provider, target)
			require.NoError(t, err)
		}
		assert.Equal(t, []string{"/aaa-111/token", "/bbb-222/token"}, *paths)
	})

	t.Run("no replacement hook sends the configured endpoint verbatim", func(t *testing.T) {
		idp, paths := newIdP(t)
		provider := newProvider(idp.URL + "/$tyk_context.jwt_claims_tid/token")

		st := &oauth2common.State{RawToken: "inbound"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := mwWithoutTykOps().fetchExchangedToken(r, st, provider, target)
		require.NoError(t, err)
		assert.Equal(t, []string{"/$tyk_context.jwt_claims_tid/token"}, *paths,
			"without a hook the variable text goes out literally — resolution is the gateway's job")
	})
}

// TestFetchExchangedToken_EndpointVariables_CacheIsPerTenant pins that a
// cached exchanged token is never served across tenants.
func TestFetchExchangedToken_EndpointVariables_CacheIsPerTenant(t *testing.T) {
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
		TokenEndpoint: idp.URL + "/$tyk_context.jwt_claims_tid/token",
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "cid", ClientSecret: "s"},
		Cache:         &oas.OAuth2ExchangeCache{Enabled: true},
	}

	m := &Middleware{Base: newFakeBase(), Spec: model.MergedAPI{OAS: &oas.OAS{}}}
	m.Cache = newSingleFlightCache(&fakeCache{items: map[string]string{}})

	// Same issuer and subject — only the endpoint-selecting variable differs.
	for _, tid := range []string{"tenant-a", "tenant-b"} {
		st := &oauth2common.State{
			Claims:           jwt.MapClaims{"iss": "https://one-issuer", "sub": "user-1"},
			ReplaceVariables: replaceVarsWith(tid),
			RawToken:         "inbound",
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, err := m.fetchExchangedToken(r, st, provider, target)
		require.NoError(t, err)
	}

	assert.Equal(t, []string{"/tenant-a/token", "/tenant-b/token"}, paths,
		"a token cached for one tenant endpoint must not be served for another")
}
