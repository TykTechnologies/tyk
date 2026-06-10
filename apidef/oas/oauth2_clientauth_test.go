package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuth2ClientAuth_PrivateKeyJWT_RoundTrip pins that the private_key_jwt
// method and its certId survive a JSON round-trip, and that certId is omitted
// when empty (so secret-auth providers serialise unchanged).
func TestOAuth2ClientAuth_PrivateKeyJWT_RoundTrip(t *testing.T) {
	ca := OAuth2ClientAuth{Method: OAuth2ClientAuthPrivateKeyJWT, ClientID: "app", CertID: "cert-1"}
	b, err := json.Marshal(ca)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"method":"private_key_jwt"`)
	assert.Contains(t, string(b), `"certId":"cert-1"`)

	var out OAuth2ClientAuth
	require.NoError(t, json.Unmarshal(b, &out))
	assert.Equal(t, ca, out)

	secret, err := json.Marshal(OAuth2ClientAuth{Method: OAuth2ClientAuthBasic, ClientID: "app", ClientSecret: "s"})
	require.NoError(t, err)
	assert.NotContains(t, string(secret), "certId")
}

// clientAuth builds a token-exchange scheme whose provider carries the given
// clientAuth, reusing the Entra-OBO test target so the provider is otherwise valid.
func clientAuth(ca *OAuth2ClientAuth) *OAuth2TokenExchange {
	return entra(func(p *OAuth2TokenExchangeProvider) { p.ClientAuth = ca })
}

// TestValidateOAuth2Schemes_ClientAuth_PrivateKeyJWT_Happy pins that a
// private_key_jwt provider with a certId validates clean (no shared secret).
func TestValidateOAuth2Schemes_ClientAuth_PrivateKeyJWT_Happy(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", clientAuth(
		&OAuth2ClientAuth{Method: OAuth2ClientAuthPrivateKeyJWT, ClientID: "app", CertID: "cert-1"}))
	assert.NoError(t, s.ValidateOAuth2Schemes())
}

// TestValidateOAuth2Schemes_ClientAuth_PrivateKeyJWT_RequiresCertID pins that
// private_key_jwt without a certId fails loud at config load.
func TestValidateOAuth2Schemes_ClientAuth_PrivateKeyJWT_RequiresCertID(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", clientAuth(
		&OAuth2ClientAuth{Method: OAuth2ClientAuthPrivateKeyJWT, ClientID: "app"}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certId")
	assert.Contains(t, err.Error(), OAuth2ClientAuthPrivateKeyJWT)
}

// TestValidateOAuth2Schemes_ClientAuth_UnknownMethod pins that an unsupported
// clientAuth method is rejected at load, not deferred to a runtime call failure.
func TestValidateOAuth2Schemes_ClientAuth_UnknownMethod(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", clientAuth(
		&OAuth2ClientAuth{Method: "mutual_tls", ClientID: "app"}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutual_tls")
}

// TestValidateOAuth2Schemes_ClientAuth_SecretMethods pins that the secret
// methods (and the empty default) are unaffected — certId is not required.
func TestValidateOAuth2Schemes_ClientAuth_SecretMethods(t *testing.T) {
	for _, m := range []string{"", OAuth2ClientAuthBasic, OAuth2ClientAuthPost} {
		s := newOAuth2WithTokenExchange("corpOAuth", clientAuth(
			&OAuth2ClientAuth{Method: m, ClientID: "app", ClientSecret: "s"}))
		assert.NoError(t, s.ValidateOAuth2Schemes(), "method %q should validate", m)
	}
}
