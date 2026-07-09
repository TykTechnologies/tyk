package oas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwtBearerProvider returns a minimal valid provider with the given grantType
// and customParams, for validation-path tests.
func jwtBearerProvider(grantType string, customParams map[string]string) OAuth2TokenExchangeProvider {
	return OAuth2TokenExchangeProvider{
		Name:          "p",
		GrantType:     grantType,
		Issuers:       []string{"https://idp.example.com"},
		TokenEndpoint: "https://idp.example.com/token",
		ClientAuth:    &OAuth2ClientAuth{ClientID: "cid"},
		CustomParams:  customParams,
	}
}

func TestOAuth2TokenExchangeProvider_GrantType_RoundTrip(t *testing.T) {
	t.Run("jwt-bearer round-trips", func(t *testing.T) {
		p := jwtBearerProvider(OAuth2ProviderGrantJWTBearer, nil)
		b, err := json.Marshal(p)
		require.NoError(t, err)

		var out OAuth2TokenExchangeProvider
		require.NoError(t, json.Unmarshal(b, &out))
		assert.Equal(t, OAuth2ProviderGrantJWTBearer, out.GrantType)
	})

	t.Run("empty grantType is omitted from JSON", func(t *testing.T) {
		p := jwtBearerProvider("", nil)
		b, err := json.Marshal(p)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "grantType")
	})
}

func TestOAuth2TokenExchangeProvider_IsJWTBearer(t *testing.T) {
	assert.False(t, (&OAuth2TokenExchangeProvider{}).IsJWTBearer())
	assert.False(t, (&OAuth2TokenExchangeProvider{GrantType: OAuth2ProviderGrantTokenExchange}).IsJWTBearer())
	assert.True(t, (&OAuth2TokenExchangeProvider{GrantType: OAuth2ProviderGrantJWTBearer}).IsJWTBearer())

	var nilProvider *OAuth2TokenExchangeProvider
	assert.False(t, nilProvider.IsJWTBearer())
}

func TestValidateOAuth2Schemes_GrantType(t *testing.T) {
	accepted := []string{"", OAuth2ProviderGrantTokenExchange, OAuth2ProviderGrantJWTBearer}
	for _, gt := range accepted {
		t.Run("accepted/"+gt, func(t *testing.T) {
			s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
				Enabled:   true,
				Providers: []OAuth2TokenExchangeProvider{jwtBearerProvider(gt, nil)},
			})
			assert.NoError(t, s.ValidateOAuth2Schemes())
		})
	}

	t.Run("unknown value rejected naming the accepted values", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled:   true,
			Providers: []OAuth2TokenExchangeProvider{jwtBearerProvider("saml-bearer", nil)},
		})
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `grantType "saml-bearer" is invalid`)
		assert.Contains(t, err.Error(), OAuth2ProviderGrantTokenExchange)
		assert.Contains(t, err.Error(), OAuth2ProviderGrantJWTBearer)
	})
}

// TestOAS_Validate_GrantType pins grantType through the full OAS.Validate
// chain — including the x-tyk-api-gateway JSON schema, which must accept the
// new key and its enum values.
func TestOAS_Validate_GrantType(t *testing.T) {
	t.Run("jwt-bearer provider passes full validation", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled: true,
			Providers: []OAuth2TokenExchangeProvider{
				jwtBearerProvider(OAuth2ProviderGrantJWTBearer, map[string]string{"requested_token_use": "on_behalf_of"}),
			},
		})
		assert.NoError(t, s.Validate(context.Background()))
	})

	t.Run("unknown grantType is rejected through full validation", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled:   true,
			Providers: []OAuth2TokenExchangeProvider{jwtBearerProvider("saml-bearer", nil)},
		})
		err := s.Validate(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "grantType")
	})
}

// Reserved customParams keys are per grant: a key is reserved only when the
// gateway itself sets it under that grant.
func TestValidateOAuth2Schemes_CustomParams_PerGrant(t *testing.T) {
	validate := func(t *testing.T, grantType, key string) error {
		t.Helper()
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled:   true,
			Providers: []OAuth2TokenExchangeProvider{jwtBearerProvider(grantType, map[string]string{key: "x"})},
		})
		return s.ValidateOAuth2Schemes()
	}

	t.Run("jwt-bearer rejects gateway-owned keys", func(t *testing.T) {
		reserved := []string{
			OAuth2FormGrantType, OAuth2FormAssertion, OAuth2FormScope,
			OAuth2FormClientID, OAuth2FormClientSecret,
			OAuth2FormClientAssertion, OAuth2FormClientAssertionType,
		}
		for _, key := range reserved {
			t.Run(key, func(t *testing.T) {
				err := validate(t, OAuth2ProviderGrantJWTBearer, key)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "customParams cannot override reserved")
				assert.Contains(t, err.Error(), key)
			})
		}
	})

	t.Run("jwt-bearer accepts keys this grant does not emit", func(t *testing.T) {
		legal := []string{"requested_token_use", OAuth2FormAudience, OAuth2FormResource, OAuth2FormSubjectToken}
		for _, key := range legal {
			t.Run(key, func(t *testing.T) {
				assert.NoError(t, validate(t, OAuth2ProviderGrantJWTBearer, key))
			})
		}
	})

	t.Run("token-exchange keeps today's reserved set", func(t *testing.T) {
		for _, key := range []string{OAuth2FormAudience, OAuth2FormResource, OAuth2FormSubjectToken} {
			t.Run("rejected/"+key, func(t *testing.T) {
				err := validate(t, OAuth2ProviderGrantTokenExchange, key)
				require.Error(t, err)
				assert.Contains(t, err.Error(), key)
			})
		}
		t.Run("accepted/requested_token_use", func(t *testing.T) {
			assert.NoError(t, validate(t, OAuth2ProviderGrantTokenExchange, "requested_token_use"))
			assert.NoError(t, validate(t, "", "requested_token_use"))
		})
	})
}
