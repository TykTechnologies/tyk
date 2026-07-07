//go:build ee || dev

package oauth2tokenexchange

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// clientAssertionTTL is the lifetime of a private_key_jwt client assertion.
// Short by design — the assertion is single-use against one token request.
const clientAssertionTTL = 5 * time.Minute

// buildClientAssertion mints a private_key_jwt client-authentication assertion
// (RFC 7523 §2.2) signed with the certificate's RSA private key. The JOSE header
// carries the SHA-256 certificate thumbprint (`x5t#S256`) so the IdP can select
// the registered public key — RS256 only, no EC support.
// Claims follow the RFC 7523 §2.2 client-authentication contract: iss = sub =
// clientID, aud = the token endpoint, a unique jti, and a short exp window.
func buildClientAssertion(cert *tls.Certificate, clientID, tokenEndpoint, jti string, now time.Time) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", fmt.Errorf("client assertion: certificate carries no DER bytes")
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("client assertion: certificate private key is %T, want *rsa.PrivateKey", cert.PrivateKey)
	}

	sum := sha256.Sum256(cert.Certificate[0])
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"jti": jti,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(clientAssertionTTL).Unix(),
	})
	token.Header["x5t#S256"] = thumbprint

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("client assertion: signing failed: %w", err)
	}
	return signed, nil
}

// newJTI returns a random token identifier for a client assertion's jti claim.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("client assertion: generating jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// addClientAssertion signs a private_key_jwt assertion with the provider's
// configured certificate and adds the client_id / client_assertion_type /
// client_assertion form fields. The assertion authenticates the gateway to the
// token endpoint in place of a shared secret.
func (m *Middleware) addClientAssertion(form url.Values, provider *oas.OAuth2TokenExchangeProvider) error {
	ca := provider.ClientAuth
	cert, err := m.Base.GetClientCertificate(ca.CertID)
	if err != nil {
		return fmt.Errorf("private_key_jwt client auth: %w", err)
	}
	jti, err := newJTI()
	if err != nil {
		return err
	}
	assertion, err := buildClientAssertion(cert, ca.ClientID, provider.TokenEndpoint, jti, time.Now())
	if err != nil {
		return err
	}
	form.Set(oas.OAuth2FormClientID, ca.ClientID)
	form.Set(oas.OAuth2FormClientAssertionType, oas.OAuth2ClientAssertionTypeJWTBearer)
	form.Set(oas.OAuth2FormClientAssertion, assertion)
	return nil
}
