//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// jwtBearerProviderWithTarget builds a jwt-bearer provider with the given default target.
func jwtBearerProviderWithTarget(target *oas.OAuth2DefaultTarget) oas.OAuth2TokenExchangeProvider {
	return oas.OAuth2TokenExchangeProvider{
		Name:          "corp-idp",
		GrantType:     oas.OAuth2ProviderGrantJWTBearer,
		TokenEndpoint: "https://idp.example.com/token",
		ClientAuth:    &oas.OAuth2ClientAuth{ClientID: "cid"},
		DefaultTarget: target,
	}
}

// TestExchangeWouldFire_JWTBearer_WithoutAudience pins that an audience-less
// jwt-bearer provider fires instead of silently passing the token upstream.
func TestExchangeWouldFire_JWTBearer_WithoutAudience(t *testing.T) {
	m := mwWithoutTykOps()
	st := &oauth2common.State{}

	t.Run("fires for a scopes-only default target", func(t *testing.T) {
		cfg := &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
			Providers: []oas.OAuth2TokenExchangeProvider{
				jwtBearerProviderWithTarget(&oas.OAuth2DefaultTarget{Scopes: []string{"Orders.Read"}}),
			},
		}}
		assert.True(t, m.exchangeWouldFire(st, cfg),
			"an audience-less jwt-bearer provider must exchange, not silently pass the inbound token upstream")
	})

	t.Run("fires with no default target at all", func(t *testing.T) {
		cfg := &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
			Providers: []oas.OAuth2TokenExchangeProvider{jwtBearerProviderWithTarget(nil)},
		}}
		assert.True(t, m.exchangeWouldFire(st, cfg))
	})

	t.Run("still does not fire for an audience-less RFC 8693 provider", func(t *testing.T) {
		p := jwtBearerProviderWithTarget(&oas.OAuth2DefaultTarget{Scopes: []string{"read"}})
		p.GrantType = oas.OAuth2ProviderGrantTokenExchange
		cfg := &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
			Providers: []oas.OAuth2TokenExchangeProvider{p},
		}}
		assert.False(t, m.exchangeWouldFire(st, cfg))
	})
}

// TestResolveExchangeTarget_JWTBearer_WithoutAudience pins that the provider
// default is honoured for jwt-bearer even when it carries scopes only.
func TestResolveExchangeTarget_JWTBearer_WithoutAudience(t *testing.T) {
	m := mwWithoutTykOps()
	st := &oauth2common.State{}

	t.Run("scopes-only default target resolves", func(t *testing.T) {
		p := jwtBearerProviderWithTarget(&oas.OAuth2DefaultTarget{Scopes: []string{"Orders.Read"}})
		got := m.resolveExchangeTarget(st, &p)
		require.NotNil(t, got)
		assert.Empty(t, got.Audience)
		assert.Equal(t, []string{"Orders.Read"}, got.Scopes)
	})

	t.Run("absent default target resolves to an empty target", func(t *testing.T) {
		p := jwtBearerProviderWithTarget(nil)
		got := m.resolveExchangeTarget(st, &p)
		require.NotNil(t, got)
		assert.Empty(t, got.Audience)
		assert.Empty(t, got.Scopes)
	})

	t.Run("RFC 8693 with a scopes-only default target still yields no target", func(t *testing.T) {
		p := jwtBearerProviderWithTarget(&oas.OAuth2DefaultTarget{Scopes: []string{"read"}})
		p.GrantType = oas.OAuth2ProviderGrantTokenExchange
		assert.Nil(t, m.resolveExchangeTarget(st, &p))
	})
}

// TestExchangeAtIdP_JWTBearer_NoAudience pins the wire shape without an
// audience: scopes verbatim, no audience or resource parameter.
func TestExchangeAtIdP_JWTBearer_NoAudience(t *testing.T) {
	var got struct {
		scope                         string
		scopePresent, audiencePresent bool
		resourcePresent               bool
	}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.scope = r.PostForm.Get(oas.OAuth2FormScope)
		_, got.scopePresent = r.PostForm[oas.OAuth2FormScope]
		_, got.audiencePresent = r.PostForm[oas.OAuth2FormAudience]
		_, got.resourcePresent = r.PostForm[oas.OAuth2FormResource]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "downstream-token", "expires_in": 120})
	}))
	defer idp.Close()

	provider := jwtBearerTestProvider(nil)
	provider.TokenEndpoint = idp.URL
	provider.ClientAuth.Method = oas.OAuth2ClientAuthPost

	target := &oauth2common.Target{Scopes: []string{"Orders.Read", "Orders.Write"}}
	tok, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound-user-token", target)
	require.NoError(t, err)
	assert.Equal(t, "downstream-token", tok)
	assert.True(t, got.scopePresent)
	assert.Equal(t, "Orders.Read Orders.Write", got.scope, "scopes are sent verbatim when there is no audience to prefix with")
	assert.False(t, got.audiencePresent)
	assert.False(t, got.resourcePresent)
}

// TestExchangeAtIdP_JWTBearer_EmptyTarget pins that an empty target produces
// an assertion-only request, with no invented scope.
func TestExchangeAtIdP_JWTBearer_EmptyTarget(t *testing.T) {
	var scopePresent bool
	var assertion string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, scopePresent = r.PostForm[oas.OAuth2FormScope]
		assertion = r.PostForm.Get(oas.OAuth2FormAssertion)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "downstream-token"})
	}))
	defer idp.Close()

	provider := jwtBearerTestProvider(nil)
	provider.TokenEndpoint = idp.URL
	provider.ClientAuth.Method = oas.OAuth2ClientAuthPost

	tok, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound-user-token", &oauth2common.Target{})
	require.NoError(t, err)
	assert.Equal(t, "downstream-token", tok)
	assert.Equal(t, "inbound-user-token", assertion)
	assert.False(t, scopePresent, "the gateway never invents a scope")
}
