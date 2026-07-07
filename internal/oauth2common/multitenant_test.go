package oauth2common

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func TestSelectExchangeProvider_RegexIssuers(t *testing.T) {
	const pattern = `regex:^https://login\.example\.com/[^/]+/v2\.0$`

	t.Run("regex entry matches any tenant issuer", func(t *testing.T) {
		providers := []oas.OAuth2TokenExchangeProvider{
			{Name: "corp", Issuers: []string{pattern}},
		}
		p := SelectExchangeProvider(providers, "https://login.example.com/tenant-123/v2.0")
		require.NotNil(t, p)
		assert.Equal(t, "corp", p.Name)
	})

	t.Run("exact beats regex across providers", func(t *testing.T) {
		providers := []oas.OAuth2TokenExchangeProvider{
			{Name: "pattern-first", Issuers: []string{pattern}},
			{Name: "exact-second", Issuers: []string{"https://login.example.com/tenant-123/v2.0"}},
		}
		p := SelectExchangeProvider(providers, "https://login.example.com/tenant-123/v2.0")
		require.NotNil(t, p)
		assert.Equal(t, "exact-second", p.Name)
	})

	t.Run("regex matches follow provider order, first match wins", func(t *testing.T) {
		providers := []oas.OAuth2TokenExchangeProvider{
			{Name: "first", Issuers: []string{pattern}},
			{Name: "second", Issuers: []string{`regex:^https://login\.example\.com/.+$`}},
		}
		p := SelectExchangeProvider(providers, "https://login.example.com/tenant-456/v2.0")
		require.NotNil(t, p)
		assert.Equal(t, "first", p.Name)
	})

	t.Run("exact entries match byte-for-byte only — metacharacters are literal", func(t *testing.T) {
		providers := []oas.OAuth2TokenExchangeProvider{
			{Name: "exact", Issuers: []string{"https://idp.example.com/realms/prod"}},
		}
		assert.Nil(t, SelectExchangeProvider(providers, "https://idpXexample.com/realms/prod"),
			"a dot in an exact entry must not act as a wildcard")
		assert.NotNil(t, SelectExchangeProvider(providers, "https://idp.example.com/realms/prod"))
	})

	t.Run("a regex entry never exact-matches its own literal string", func(t *testing.T) {
		providers := []oas.OAuth2TokenExchangeProvider{
			{Name: "corp", Issuers: []string{pattern}},
		}
		assert.Nil(t, SelectExchangeProvider(providers, pattern))
	})
}

func TestResolveTokenEndpoint(t *testing.T) {
	claims := jwt.MapClaims{"tid": "aaa-111"}

	t.Run("no placeholder passes through untouched", func(t *testing.T) {
		got, err := ResolveTokenEndpoint("https://idp.example.com/token", claims)
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/token", got)
	})

	t.Run("claim value lands in the endpoint path", func(t *testing.T) {
		got, err := ResolveTokenEndpoint("https://login.example.com/{claim.tid}/oauth2/v2.0/token", claims)
		require.NoError(t, err)
		assert.Equal(t, "https://login.example.com/aaa-111/oauth2/v2.0/token", got)
	})

	t.Run("token lacking the claim is rejected", func(t *testing.T) {
		_, err := ResolveTokenEndpoint("https://login.example.com/{claim.tid}/token", jwt.MapClaims{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tid")
	})

	t.Run("claim value failing the charset guard is rejected", func(t *testing.T) {
		for _, bad := range []string{"../evil", "a b", "x/y", "a?b=c", ".", ".."} {
			_, err := ResolveTokenEndpoint("https://login.example.com/{claim.tid}/token", jwt.MapClaims{"tid": bad})
			require.Error(t, err, "value %q must fail the charset guard", bad)
		}
	})

	t.Run("non-string claim value is rejected", func(t *testing.T) {
		_, err := ResolveTokenEndpoint("https://login.example.com/{claim.tid}/token", jwt.MapClaims{"tid": 42})
		require.Error(t, err)
	})
}
