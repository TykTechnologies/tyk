package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuth2ActorToken_RoundTripPreservesAllFields(t *testing.T) {
	strip, required, mayAct := false, false, true
	te := &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{
				Name:          "primary",
				Issuers:       []string{"https://idp.example.com"},
				TokenEndpoint: "https://idp.example.com/oauth/token",
				ClientAuth:    &OAuth2ClientAuth{ClientID: "tyk-gateway"},
				ActorToken: &OAuth2ActorToken{
					Source:         OAuth2ActorSourceClientCredentials,
					ActorTokenType: OAuth2TokenTypeJWT,
					RequireMayAct:  &mayAct,
					ClientCredentials: &OAuth2ActorClientCredentials{
						TokenEndpoint: "https://idp.example.com/oauth/token",
						ClientID:      "tyk-gateway-actor",
						ClientSecret:  "vault://kv/tyk/actor",
						Scopes:        []string{"agent"},
					},
					Header: &OAuth2ActorHeader{Name: "X-Delegate", Strip: &strip, Required: &required},
					Static: &OAuth2ActorStatic{Token: "env://ACTOR_TOKEN"},
				},
			},
		},
	}

	b, err := json.Marshal(te)
	require.NoError(t, err)

	var out OAuth2TokenExchange
	require.NoError(t, json.Unmarshal(b, &out))

	require.Len(t, out.Providers, 1)
	at := out.Providers[0].ActorToken
	require.NotNil(t, at)
	assert.Equal(t, OAuth2ActorSourceClientCredentials, at.Source)
	assert.Equal(t, OAuth2TokenTypeJWT, at.ActorTokenType)
	require.NotNil(t, at.RequireMayAct)
	assert.True(t, *at.RequireMayAct)
	require.NotNil(t, at.ClientCredentials)
	assert.Equal(t, "tyk-gateway-actor", at.ClientCredentials.ClientID)
	assert.Equal(t, "vault://kv/tyk/actor", at.ClientCredentials.ClientSecret)
	assert.Equal(t, []string{"agent"}, at.ClientCredentials.Scopes)
	require.NotNil(t, at.Header)
	assert.Equal(t, "X-Delegate", at.Header.Name)
	require.NotNil(t, at.Header.Strip)
	assert.False(t, *at.Header.Strip)
	require.NotNil(t, at.Static)
	assert.Equal(t, "env://ACTOR_TOKEN", at.Static.Token)
}

func TestOAuth2ActorToken_OmittedWhenAbsent(t *testing.T) {
	b, err := json.Marshal(OAuth2TokenExchangeProvider{Name: "p"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "actorToken")
}

func teProviderWithActor(at *OAuth2ActorToken) *OAuth2TokenExchange {
	return &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "p", Issuers: []string{"https://a"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "ca"}, ActorToken: at},
		},
	}
}

func TestValidateOAuth2Schemes_ActorToken_InvalidSource(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{Source: "bogus"}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `actorToken.source "bogus" is invalid`)
}

func TestValidateOAuth2Schemes_ActorToken_CCRequiresSubBlock(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{Source: OAuth2ActorSourceClientCredentials}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires clientCredentials.tokenEndpoint and clientId")
}

func TestValidateOAuth2Schemes_ActorToken_StaticRequiresToken(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{Source: OAuth2ActorSourceStatic, Static: &OAuth2ActorStatic{}}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires static.token")
}

func TestValidateOAuth2Schemes_ActorToken_Happy(t *testing.T) {
	cc := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{
		Source:            OAuth2ActorSourceClientCredentials,
		ClientCredentials: &OAuth2ActorClientCredentials{TokenEndpoint: "https://idp/token", ClientID: "tyk-gateway-actor"},
	}))
	assert.NoError(t, cc.ValidateOAuth2Schemes())

	hdr := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{Source: OAuth2ActorSourceHeader}))
	assert.NoError(t, hdr.ValidateOAuth2Schemes(), "header sub-block is optional; defaults apply")

	stat := newOAuth2WithTokenExchange("corpOAuth", teProviderWithActor(&OAuth2ActorToken{Source: OAuth2ActorSourceStatic, Static: &OAuth2ActorStatic{Token: "t"}}))
	assert.NoError(t, stat.ValidateOAuth2Schemes())
}

func TestValidateOAuth2Schemes_ActorTokenType(t *testing.T) {
	base := func(tokenType string) *OAuth2ActorToken {
		return &OAuth2ActorToken{
			Source:            OAuth2ActorSourceClientCredentials,
			ActorTokenType:    tokenType,
			ClientCredentials: &OAuth2ActorClientCredentials{TokenEndpoint: "https://idp/token", ClientID: "actor"},
		}
	}

	t.Run("empty defaults to access_token and is accepted", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("x", teProviderWithActor(base("")))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("explicit access_token accepted", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("x", teProviderWithActor(base(OAuth2TokenTypeAccessToken)))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("jwt override accepted", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("x", teProviderWithActor(base(OAuth2TokenTypeJWT)))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("unknown URN rejected naming the allowed values", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("x", teProviderWithActor(base("urn:bogus")))
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "actorToken.actorTokenType")
		assert.Contains(t, err.Error(), OAuth2TokenTypeAccessToken)
		assert.Contains(t, err.Error(), OAuth2TokenTypeJWT)
	})
}
