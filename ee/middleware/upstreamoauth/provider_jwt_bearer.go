package upstreamoauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

const (
	// defaultJWTBearerAssertionTTL is the lifetime of the signed JWT when expiresIn is unset.
	// It fits Salesforce's requirement that exp is within 3 minutes of issue.
	defaultJWTBearerAssertionTTL = 2 * time.Minute

	// defaultJWTBearerTokenTTL is how long an access token is cached when the IdP
	// response carries no expires_in (Salesforce omits it). Kept short so a revoked
	// or expired session is picked up quickly.
	defaultJWTBearerTokenTTL = 5 * time.Minute

	// maxJWTBearerResponseBytes caps the token endpoint response body read.
	maxJWTBearerResponseBytes = 1 << 20

	oauth2ErrInvalidClient         = "invalid_client"
	oauth2ErrInvalidGrant          = "invalid_grant"
	oauth2ErrUnauthorizedClient    = "unauthorized_client"
	oauth2ErrInvalidClientMetadata = "invalid_client_metadata"
	oauth2ErrAccessDenied          = "access_denied"

	// defaultJWTBearerHTTPTimeout matches the OAuth service timeout used by
	// internal/httpclient.ExternalHTTPClientFactory.
	defaultJWTBearerHTTPTimeout = 15 * time.Second
)

// defaultJWTBearerHTTPClient is used when no external-services OAuth client is
// configured. Unlike http.DefaultClient it has a timeout, so an unresponsive
// token endpoint cannot hang the request indefinitely.
var defaultJWTBearerHTTPClient = &http.Client{Timeout: defaultJWTBearerHTTPTimeout}

// JWTBearerSigningError is returned when the JWT assertion cannot be built:
// the certificate is missing, has no (RSA) private key, or signing fails.
// It maps to HTTP 500 and the IdP is never called.
type JWTBearerSigningError struct {
	CertID string
	Err    error
}

func (e *JWTBearerSigningError) Error() string {
	return fmt.Sprintf("jwt bearer: unable to sign assertion with certificate %q: %v", e.CertID, e.Err)
}

func (e *JWTBearerSigningError) Unwrap() error { return e.Err }

// JWTBearerIdPError is returned when the token endpoint answers with an error
// or an unusable response. StatusCode is the HTTP status the gateway returns to
// the client: 401 or 403 for a rejection, 500 when the IdP is unavailable.
type JWTBearerIdPError struct {
	// IdPStatus is the HTTP status returned by the token endpoint.
	IdPStatus int
	// IdPError is the OAuth `error` code returned by the token endpoint.
	IdPError string
	// Description is the OAuth `error_description` (or a truncated raw body).
	Description string
	// StatusCode is the HTTP status the gateway responds with.
	StatusCode int
}

func (e *JWTBearerIdPError) Error() string {
	return fmt.Sprintf("jwt bearer: token endpoint returned an error: status=%d error=%s description=%s",
		e.IdPStatus, e.IdPError, e.Description)
}

// jwtBearerRejectionStatus maps a token endpoint error to the status the
// gateway returns to the client.
func jwtBearerRejectionStatus(idpStatus int, idpErr string) int {
	// A 5xx or 429 means the IdP is unavailable, not that it rejected the
	// assertion. Report it as a gateway error, the same as an unreachable IdP,
	// so an outage does not look like bad credentials.
	if idpStatus >= http.StatusInternalServerError || idpStatus == http.StatusTooManyRequests {
		return http.StatusInternalServerError
	}

	if idpStatus == http.StatusUnauthorized || idpStatus == http.StatusForbidden {
		return idpStatus
	}

	switch idpErr {
	case oauth2ErrAccessDenied:
		return http.StatusForbidden
	case oauth2ErrInvalidClient, oauth2ErrInvalidGrant, oauth2ErrUnauthorizedClient, oauth2ErrInvalidClientMetadata:
		// TT-16926: HTTP 400 + invalid_grant (the usual answer to a bad assertion)
		// is intentionally mapped to 401. This may be revisited if product guidance changes.
		return http.StatusUnauthorized
	default:
		// Unknown 4xx IdP errors are treated as an authentication failure rather
		// than a gateway error, so a rejected assertion is not reported as a 5xx.
		return http.StatusUnauthorized
	}
}

// tokenErrorStatus returns the HTTP status for a token acquisition error.
// Only JWT Bearer IdP rejections differ from the historical HTTP 500.
func tokenErrorStatus(err error) int {
	var idpErr *JWTBearerIdPError
	if errors.As(err, &idpErr) {
		return idpErr.StatusCode
	}
	return http.StatusInternalServerError
}

// JWTBearerOAuthProvider implements the OAuth 2.0 JWT Bearer grant (RFC 7523 §2.1).
type JWTBearerOAuthProvider struct{}

// errJWTBearerClientMessage is what the API consumer sees when the grant fails.
const errJWTBearerClientMessage = "upstream authentication failed"

// jwtBearerClientError keeps token acquisition details (the IdP error
// description, the certificate ID) out of the response to the API consumer.
// The full error is logged, sent with the UpstreamOAuthError event, and stays
// reachable through errors.As / errors.Is.
type jwtBearerClientError struct{ err error }

func (e *jwtBearerClientError) Error() string { return errJWTBearerClientMessage }

func (e *jwtBearerClientError) Unwrap() error { return e.err }

func (p *JWTBearerOAuthProvider) getOAuthToken(r *http.Request, mw *Middleware) (string, error) {
	var (
		token string
		err   error
	)

	// Validation rejects the grant for classic APIs when they are saved through
	// the Gateway or Dashboard API. A classic definition loaded from disk skips
	// that, so refuse it here as well.
	if mw.Spec.IsOAS {
		client := JWTBearerClient{mw: mw}
		token, err = client.GetToken(r)
	} else {
		err = apidef.ErrUpstreamOAuthJWTBearerOASOnly
	}

	if err != nil {
		logJWTBearerError(mw, err)
		_, err = handleOAuthError(r, mw, err)
		return "", &jwtBearerClientError{err: err}
	}

	return fmt.Sprintf("Bearer %s", token), nil
}

func (p *JWTBearerOAuthProvider) getHeaderName(mw *Middleware) string {
	return mw.Spec.UpstreamAuth.OAuth.JWTBearer.Header.Name
}

func (p *JWTBearerOAuthProvider) headerEnabled(mw *Middleware) bool {
	return mw.Spec.UpstreamAuth.OAuth.JWTBearer.Header.Enabled
}

// logJWTBearerError logs the failure cause without the assertion, key or token.
func logJWTBearerError(mw *Middleware, err error) {
	if mw.Base == nil {
		return
	}

	var (
		signErr *JWTBearerSigningError
		idpErr  *JWTBearerIdPError
	)

	switch {
	case errors.As(err, &signErr):
		mw.Logger().WithFields(logrus.Fields{
			"cert_id": signErr.CertID,
			"error":   signErr.Err.Error(),
		}).Error("Upstream OAuth JWT Bearer: unable to sign assertion")
	case errors.As(err, &idpErr):
		mw.Logger().WithFields(logrus.Fields{
			"idp_status":            idpErr.IdPStatus,
			"idp_error":             idpErr.IdPError,
			"idp_error_description": idpErr.Description,
			"status":                idpErr.StatusCode,
		}).Error("Upstream OAuth JWT Bearer: token endpoint returned an error")
	default:
		mw.Logger().WithError(err).Error("Upstream OAuth JWT Bearer: failed to obtain token")
	}
}

// JWTBearerClient obtains and caches access tokens using the JWT Bearer grant.
type JWTBearerClient struct {
	mw *Middleware
	// now is overridable in tests.
	now func() time.Time
}

func (client *JWTBearerClient) config() apidef.UpstreamOAuthJWTBearer {
	return client.mw.Spec.UpstreamAuth.OAuth.JWTBearer
}

func (client *JWTBearerClient) timeNow() time.Time {
	if client.now != nil {
		return client.now()
	}
	return time.Now()
}

// GetToken returns the access token from cache, or obtains a new one.
func (client *JWTBearerClient) GetToken(r *http.Request) (string, error) {
	cacheKey := generateJWTBearerCacheKey(client.mw.Spec.UpstreamAuth.OAuth, client.mw.Spec.APIID)
	secret := client.mw.Gw.GetConfig().Secret

	return getToken(r, cacheKey, client.ObtainToken, secret, nil, client.mw.jwtBearerStorageHandler)
}

// ObtainToken signs a JWT assertion and exchanges it at the token endpoint.
// The token endpoint is not called when the assertion cannot be signed.
func (client *JWTBearerClient) ObtainToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := client.config()

	assertion, err := client.signAssertion(cfg)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set(oas.OAuth2FormGrantType, oas.OAuth2GrantTypeJWTBearer)
	form.Set(oas.OAuth2FormAssertion, assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("jwt bearer: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := createOAuthHTTPClient(client.mw)
	if httpClient == nil {
		httpClient = defaultJWTBearerHTTPClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwt bearer: token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWTBearerResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("jwt bearer: reading token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		idpErr, description := oauth2common.DecodeIdPError(body)
		return nil, &JWTBearerIdPError{
			IdPStatus:   resp.StatusCode,
			IdPError:    idpErr,
			Description: description,
			StatusCode:  jwtBearerRejectionStatus(resp.StatusCode, idpErr),
		}
	}

	return client.parseTokenResponse(resp.StatusCode, body)
}

func (client *JWTBearerClient) parseTokenResponse(status int, body []byte) (*oauth2.Token, error) {
	var tr struct {
		AccessToken string      `json:"access_token"`
		TokenType   string      `json:"token_type"`
		ExpiresIn   json.Number `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return nil, &JWTBearerIdPError{
			IdPStatus:   status,
			IdPError:    "invalid_token_response",
			Description: "token endpoint response has no access_token",
			StatusCode:  http.StatusUnauthorized,
		}
	}

	ttl := defaultJWTBearerTokenTTL
	if secs, err := tr.ExpiresIn.Int64(); err == nil && secs > 0 {
		ttl = time.Duration(secs) * time.Second
	}

	return &oauth2.Token{
		AccessToken: tr.AccessToken,
		TokenType:   tr.TokenType,
		Expiry:      client.timeNow().Add(ttl),
	}, nil
}

// signAssertion builds the RFC 7523 §2.1 authorization grant JWT, signed RS256
// with the private key of the configured certificate.
func (client *JWTBearerClient) signAssertion(cfg apidef.UpstreamOAuthJWTBearer) (string, error) {
	signErr := func(err error) error {
		return &JWTBearerSigningError{CertID: cfg.CertID, Err: err}
	}

	cert, err := client.mw.Base.GetClientCertificate(cfg.CertID)
	if err != nil {
		return "", signErr(err)
	}
	if cert == nil {
		return "", signErr(errors.New("certificate not found"))
	}

	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", signErr(fmt.Errorf("certificate private key is %T, want *rsa.PrivateKey", cert.PrivateKey))
	}

	jti, err := newJWTBearerJTI()
	if err != nil {
		return "", signErr(err)
	}

	lifetime := time.Duration(cfg.ExpiresIn)
	if lifetime <= 0 {
		lifetime = defaultJWTBearerAssertionTTL
	}

	now := client.timeNow()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": cfg.Issuer,
		"sub": cfg.Subject,
		"aud": cfg.Audience,
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"jti": jti,
	})

	signed, err := token.SignedString(key)
	if err != nil {
		return "", signErr(fmt.Errorf("signing failed: %w", err))
	}

	return signed, nil
}

func newJWTBearerJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateJWTBearerCacheKey derives the token cache key for the JWT Bearer grant.
// Each field is length-prefixed before hashing so values containing separators
// (such as '|', newlines or null bytes) cannot make two configs collide.
func generateJWTBearerCacheKey(config apidef.UpstreamOAuth, apiId string) string {
	jb := config.JWTBearer
	hash := sha256.New()
	for _, field := range []string{
		"jwt",
		apiId,
		jb.TokenURL,
		jb.CertID,
		jb.Issuer,
		jb.Subject,
		jb.Audience,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		hash.Write(length[:])
		hash.Write([]byte(field))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
