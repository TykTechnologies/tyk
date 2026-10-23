package oauth2common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// jwtBearerProviderFixture is providerFixture with the RFC 7523 grant selected.
func jwtBearerProviderFixture(target *oas.OAuth2DefaultTarget) oas.OAuth2TokenExchangeProvider {
	p := providerFixture("p", "https://idp", "https://idp/token", target)
	p.GrantType = oas.OAuth2ProviderGrantJWTBearer
	return p
}

// TestMergeTargetForProvider_JWTBearer_AudienceOptional pins that jwt-bearer
// resolves a target without an audience (RFC 7523 has no audience parameter).
func TestMergeTargetForProvider_JWTBearer_AudienceOptional(t *testing.T) {
	t.Run("scopes-only provider default resolves with an empty audience", func(t *testing.T) {
		prov := jwtBearerProviderFixture(&oas.OAuth2DefaultTarget{Scopes: []string{"api://orders/Orders.Read"}})
		got := MergeTargetForProvider(nil, &prov, nil)
		require.NotNil(t, got, "jwt-bearer does not need an audience to resolve a target")
		assert.Empty(t, got.Audience)
		assert.Equal(t, []string{"api://orders/Orders.Read"}, got.Scopes)
	})

	t.Run("per-op scopes resolve with no audience anywhere", func(t *testing.T) {
		prov := jwtBearerProviderFixture(nil)
		ex := &oas.OAuth2Exchange{Scopes: []string{"Orders.Read"}}
		got := MergeTargetForProvider(ex, &prov, nil)
		require.NotNil(t, got)
		assert.Empty(t, got.Audience)
		assert.Equal(t, []string{"Orders.Read"}, got.Scopes)
	})

	t.Run("no target configuration at all still resolves", func(t *testing.T) {
		// An assertion-only request is valid RFC 7523; the IdP decides.
		prov := jwtBearerProviderFixture(nil)
		got := MergeTargetForProvider(nil, &prov, nil)
		require.NotNil(t, got)
		assert.Empty(t, got.Audience)
		assert.Empty(t, got.Scopes)
	})

	t.Run("an audience is still honoured when set", func(t *testing.T) {
		prov := jwtBearerProviderFixture(&oas.OAuth2DefaultTarget{Audience: "api://orders", Scopes: []string{"Orders.Read"}})
		got := MergeTargetForProvider(nil, &prov, nil)
		require.NotNil(t, got)
		assert.Equal(t, "api://orders", got.Audience)
		assert.Equal(t, []string{"Orders.Read"}, got.Scopes)
	})
}

// TestMergeTargetForProvider_TokenExchange_StillRequiresAudience guards the
// RFC 8693 path: an unresolvable audience stays a misconfiguration.
func TestMergeTargetForProvider_TokenExchange_StillRequiresAudience(t *testing.T) {
	t.Run("default grant with scopes but no audience yields no target", func(t *testing.T) {
		prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Scopes: []string{"read"}})
		assert.Nil(t, MergeTargetForProvider(nil, &prov, nil))
	})

	t.Run("explicit token-exchange grant with no audience yields no target", func(t *testing.T) {
		prov := providerFixture("p", "https://idp", "https://idp/token", nil)
		prov.GrantType = oas.OAuth2ProviderGrantTokenExchange
		ex := &oas.OAuth2Exchange{Scopes: []string{"read"}}
		assert.Nil(t, MergeTargetForProvider(ex, &prov, nil))
	})

	t.Run("a nil provider with no audience yields no target", func(t *testing.T) {
		assert.Nil(t, MergeTargetForProvider(&oas.OAuth2Exchange{Scopes: []string{"read"}}, nil, nil))
	})
}
