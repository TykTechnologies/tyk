package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multiTenantScheme builds a one-provider token-exchange scheme with the given
// issuers and tokenEndpoint.
func multiTenantScheme(issuers []string, tokenEndpoint string) *OAS {
	return newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{{
			Name:          "corp-idp",
			GrantType:     OAuth2ProviderGrantJWTBearer,
			Issuers:       issuers,
			TokenEndpoint: tokenEndpoint,
			ClientAuth:    &OAuth2ClientAuth{ClientID: "cid"},
		}},
	})
}

func TestValidateOAuth2Schemes_RegexIssuers(t *testing.T) {
	const canonical = `regex:^https://login\.example\.com/[^/]+/v2\.0$`

	t.Run("canonical anchored entry loads", func(t *testing.T) {
		s := multiTenantScheme([]string{canonical}, "https://login.example.com/common/token")
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("non-compiling entry is a load error", func(t *testing.T) {
		s := multiTenantScheme([]string{"regex:^https://[unclosed"}, "https://idp/token")
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "regex")
	})

	t.Run("unanchored entry is a load error naming the anchoring requirement", func(t *testing.T) {
		s := multiTenantScheme([]string{`regex:https://login\.example\.com/[^/]+/v2\.0`}, "https://idp/token")
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "anchored")
	})

	t.Run("exact entries with regex metacharacters still validate unchanged", func(t *testing.T) {
		s := multiTenantScheme([]string{"https://idp.example.com/realms/prod"}, "https://idp/token")
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("duplicate exact issuers across providers stay rejected", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled: true,
			Providers: []OAuth2TokenExchangeProvider{
				{Name: "a", Issuers: []string{"https://shared"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
				{Name: "b", Issuers: []string{"https://shared"}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
			},
		})
		require.Error(t, s.ValidateOAuth2Schemes())
	})

	t.Run("identical regex entries on two providers are not an overlap error — order decides", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled: true,
			Providers: []OAuth2TokenExchangeProvider{
				{Name: "a", Issuers: []string{canonical}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
				{Name: "b", Issuers: []string{canonical}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
			},
		})
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})
}

func TestValidateOAuth2Schemes_TokenEndpointPlaceholder(t *testing.T) {
	t.Run("placeholder in the path loads", func(t *testing.T) {
		s := multiTenantScheme([]string{"https://idp"}, "https://login.example.com/{claim.tid}/oauth2/v2.0/token")
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("placeholder in host position is a load error", func(t *testing.T) {
		s := multiTenantScheme([]string{"https://idp"}, "https://{claim.tid}.evil.example/token")
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "placeholder")
	})
}
