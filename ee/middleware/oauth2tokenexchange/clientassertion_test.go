//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// selfSignedRSACert returns a *tls.Certificate with a populated Leaf, backed by
// a freshly generated RSA key — the shape CertificateManager.List hands back.
func selfSignedRSACert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tyk-obo"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestBuildClientAssertion(t *testing.T) {
	cert := selfSignedRSACert(t)
	now := time.Unix(1_700_000_000, 0)
	const clientID = "11111111-2222-3333-4444-555555555555"
	const endpoint = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"

	// parser verifies the signature but skips exp/nbf checks so the fixed `now`
	// above stays deterministic — these tests assert signing, not current validity.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	keyFn := func(*jwt.Token) (interface{}, error) { return cert.Leaf.PublicKey, nil }

	t.Run("produces an RS256 JWT that verifies against the certificate", func(t *testing.T) {
		s, err := buildClientAssertion(cert, clientID, endpoint, "jti-1", now)
		require.NoError(t, err)

		parsed, err := parser.Parse(s, keyFn)
		require.NoError(t, err)
		assert.True(t, parsed.Valid)
		assert.Equal(t, "RS256", parsed.Method.Alg())
	})

	t.Run("sets the JOSE header with the SHA-256 cert thumbprint (x5t#S256)", func(t *testing.T) {
		s, err := buildClientAssertion(cert, clientID, endpoint, "jti-1", now)
		require.NoError(t, err)

		parsed, _ := parser.Parse(s, keyFn)
		assert.Equal(t, "JWT", parsed.Header["typ"])
		assert.Equal(t, "RS256", parsed.Header["alg"])

		sum := sha256.Sum256(cert.Certificate[0])
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		assert.Equal(t, want, parsed.Header["x5t#S256"], "thumbprint must be base64url(SHA-256(DER))")
	})

	t.Run("sets the assertion claims per RFC 7523 / Entra", func(t *testing.T) {
		s, err := buildClientAssertion(cert, clientID, endpoint, "jti-unique", now)
		require.NoError(t, err)

		claims := jwt.MapClaims{}
		_, err = parser.ParseWithClaims(s, claims, keyFn)
		require.NoError(t, err)

		assert.Equal(t, clientID, claims["iss"], "iss must be the client id")
		assert.Equal(t, clientID, claims["sub"], "sub must equal iss")
		assert.Equal(t, endpoint, claims["aud"], "aud must be the token endpoint")
		assert.Equal(t, "jti-unique", claims["jti"])
		assert.EqualValues(t, now.Unix(), claims["iat"])
		assert.EqualValues(t, now.Unix(), claims["nbf"])
		assert.EqualValues(t, now.Add(5*time.Minute).Unix(), claims["exp"], "exp is a short 5-minute window")
	})

	t.Run("rejects a certificate carrying no DER bytes", func(t *testing.T) {
		_, err := buildClientAssertion(&tls.Certificate{PrivateKey: cert.PrivateKey}, clientID, endpoint, "j", now)
		require.Error(t, err)
	})

	t.Run("rejects a non-RSA private key (Entra cert auth is RSA-only)", func(t *testing.T) {
		eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecCert := &tls.Certificate{Certificate: cert.Certificate, Leaf: cert.Leaf, PrivateKey: eckey}
		_, err = buildClientAssertion(ecCert, clientID, endpoint, "j", now)
		require.Error(t, err)
	})
}

// TestExchangeAtIdP_PrivateKeyJWT proves the exchange call authenticates with a
// signed client assertion (no shared secret) when the provider's clientAuth
// method is private_key_jwt.
func TestExchangeAtIdP_PrivateKeyJWT(t *testing.T) {
	cert := selfSignedRSACert(t)
	target := &oauth2common.Target{Audience: "api://acme", Scopes: []string{"api://acme/.default"}}

	var got struct {
		clientID, assertion, assertionType string
		basicOK                            bool
	}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.clientID = r.PostForm.Get(oas.OAuth2FormClientID)
		got.assertion = r.PostForm.Get(oas.OAuth2FormClientAssertion)
		got.assertionType = r.PostForm.Get(oas.OAuth2FormClientAssertionType)
		_, _, got.basicOK = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged", "expires_in": 300})
	}))
	defer idp.Close()

	m := &Middleware{Base: &fakeBase{cert: cert}, Spec: model.MergedAPI{OAS: &oas.OAS{}}}
	provider := &oas.OAuth2TokenExchangeProvider{
		Name:          "entra",
		Flow:          oas.OAuth2FlowOnBehalfOf,
		TokenEndpoint: idp.URL,
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPrivateKeyJWT, ClientID: "app-id", CertID: "cert-1"},
	}

	tok, _, err := m.exchangeAtIdP(context.Background(), provider, "inbound-user-token", "", target)
	require.NoError(t, err)
	assert.Equal(t, "exchanged", tok)

	assert.Equal(t, "app-id", got.clientID)
	assert.Equal(t, oas.OAuth2ClientAssertionTypeJWTBearer, got.assertionType)
	assert.False(t, got.basicOK, "private_key_jwt must not send basic auth")
	require.NotEmpty(t, got.assertion, "a signed client assertion must reach the IdP")

	// the assertion the IdP received verifies against the configured certificate
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(got.assertion, func(*jwt.Token) (interface{}, error) { return cert.Leaf.PublicKey, nil })
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "app-id", claims["iss"])
	assert.Equal(t, idp.URL, claims["aud"])
}

// TestExchangeAtIdP_PrivateKeyJWT_CertError surfaces a missing/unloadable
// certificate as an error before any IdP call.
func TestExchangeAtIdP_PrivateKeyJWT_CertError(t *testing.T) {
	m := &Middleware{Base: &fakeBase{certErr: assert.AnError}, Spec: model.MergedAPI{OAS: &oas.OAS{}}}
	provider := &oas.OAuth2TokenExchangeProvider{
		Name:          "entra",
		TokenEndpoint: "https://idp.example/token",
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPrivateKeyJWT, ClientID: "app-id", CertID: "missing"},
	}
	_, _, err := m.exchangeAtIdP(context.Background(), provider, "inbound", "", &oauth2common.Target{Audience: "api://x", Scopes: []string{"api://x/.default"}})
	require.Error(t, err)
}
