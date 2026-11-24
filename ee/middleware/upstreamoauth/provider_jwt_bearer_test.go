package upstreamoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/service/core"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

const (
	jwtTestIssuer   = "consumer-key"
	jwtTestSubject  = "user@example.com"
	jwtTestAudience = "https://login.salesforce.com"
	jwtTestCertID   = "cert-id"
)

// memStorage is an in-memory Storage; expire() simulates the cache TTL elapsing.
type memStorage struct {
	mu       sync.Mutex
	data     map[string]string
	ttls     map[string]int64
	setCalls int
}

func newMemStorage() *memStorage {
	return &memStorage{data: map[string]string{}, ttls: map[string]int64{}}
}

func (s *memStorage) GetKey(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (s *memStorage) SetKey(key, value string, ttl int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setCalls++
	s.data[key] = value
	s.ttls[key] = ttl
	return nil
}

func (s *memStorage) Lock(string, time.Duration) (bool, error) { return true, nil }

func (s *memStorage) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
}

func newTestRSACert(t *testing.T) (*tls.Certificate, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwt-bearer-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, &key.PublicKey
}

// mockIdP is a token endpoint that verifies the JWT Bearer assertion.
type mockIdP struct {
	*httptest.Server
	calls int32
	// claims holds the claims of the last verified assertion.
	claims jwt.MapClaims
}

func newMockIdP(t *testing.T, pub *rsa.PublicKey, handler func(w http.ResponseWriter, call int32)) *mockIdP {
	t.Helper()
	idp := &mockIdP{}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&idp.calls, 1)

		if !assert.Equal(t, http.MethodPost, r.Method) ||
			!assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type")) ||
			!assert.NoError(t, r.ParseForm()) ||
			!assert.Equal(t, oas.OAuth2GrantTypeJWTBearer, r.PostForm.Get("grant_type")) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assert.Empty(t, r.Header.Get("Authorization"), "no client authentication is sent")
		assert.Empty(t, r.PostForm.Get("client_secret"))

		if pub != nil {
			claims := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(r.PostForm.Get("assertion"), claims, func(tok *jwt.Token) (interface{}, error) {
				if tok.Method != jwt.SigningMethodRS256 {
					return nil, fmt.Errorf("unexpected alg %v", tok.Header["alg"])
				}
				return pub, nil
			})
			if !assert.NoError(t, err) || !assert.True(t, token.Valid) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			assert.NotContains(t, token.Header, "kid")
			assert.NotContains(t, token.Header, "x5t#S256")
			idp.claims = claims
		}

		handler(w, call)
	}))
	t.Cleanup(idp.Close)
	return idp
}

func (i *mockIdP) callCount() int { return int(atomic.LoadInt32(&i.calls)) }

func writeTokenResponse(t *testing.T, w http.ResponseWriter, accessToken string, expiresIn int) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"access_token": accessToken, "token_type": "Bearer"}
	if expiresIn > 0 {
		resp["expires_in"] = expiresIn
	}
	err := json.NewEncoder(w).Encode(resp)
	assert.NoError(t, err)
}

func writeOAuthError(t *testing.T, w http.ResponseWriter, status int, code string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "rejected by test IdP"})
	assert.NoError(t, err)
}

func newJWTBearerMiddleware(tokenURL string, base *mockBaseMiddleware, store Storage, mutate func(*apidef.UpstreamOAuthJWTBearer)) *Middleware {
	jb := apidef.UpstreamOAuthJWTBearer{
		TokenURL: tokenURL,
		CertID:   jwtTestCertID,
		Issuer:   jwtTestIssuer,
		Subject:  jwtTestSubject,
		Audience: jwtTestAudience,
	}
	if mutate != nil {
		mutate(&jb)
	}

	spec := model.MergedAPI{
		APIDefinition: &apidef.APIDefinition{
			APIID: "jwt-api",
			IsOAS: true,
			UpstreamAuth: apidef.UpstreamAuth{
				Enabled: true,
				OAuth: apidef.UpstreamOAuth{
					Enabled:               true,
					AllowedAuthorizeTypes: []string{JWTBearerAuthorizeType},
					JWTBearer:             jb,
				},
			},
		},
	}

	gw := &mockGateway{config: config.Config{Secret: "test-secret"}}
	ccStore, pwStore := &mockStorage{}, &mockStorage{}
	return NewMiddleware(gw, base, spec, ccStore, pwStore, store)
}

// processAndFill runs the middleware and returns the headers the upstream request would carry.
func processAndFill(t *testing.T, m *Middleware) (http.Header, int, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://gateway/api", nil)
	err, code := m.ProcessRequest(httptest.NewRecorder(), req, nil)
	if err != nil {
		return nil, code, err
	}

	provider := core.GetUpstreamAuth(req)
	require.NotNil(t, provider)
	upstreamReq := httptest.NewRequest(http.MethodGet, "http://upstream/api", nil)
	provider.Fill(upstreamReq)
	return upstreamReq.Header, code, nil
}

func TestJWTBearer_AuthenticatesAndSetsUpstreamHeader(t *testing.T) {
	cert, pub := newTestRSACert(t)
	idp := newMockIdP(t, pub, func(w http.ResponseWriter, _ int32) {
		writeTokenResponse(t, w, "sf-access-token", 3600)
	})

	t.Run("default lifetime and Authorization header", func(t *testing.T) {
		base := &mockBaseMiddleware{cert: cert}
		m := newJWTBearerMiddleware(idp.URL, base, newMemStorage(), nil)

		headers, code, err := processAndFill(t, m)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "Bearer sf-access-token", headers.Get("Authorization"))
		assert.Equal(t, []string{jwtTestCertID}, base.certCalls)

		claims := idp.claims
		require.NotNil(t, claims)
		assert.Equal(t, jwtTestIssuer, claims["iss"])
		assert.Equal(t, jwtTestSubject, claims["sub"])
		assert.Equal(t, jwtTestAudience, claims["aud"])
		assert.NotEmpty(t, claims["jti"])
		iat, exp := claims["iat"].(float64), claims["exp"].(float64)
		assert.Equal(t, defaultJWTBearerAssertionTTL.Seconds(), exp-iat)
	})

	t.Run("custom lifetime and header", func(t *testing.T) {
		base := &mockBaseMiddleware{cert: cert}
		m := newJWTBearerMiddleware(idp.URL, base, newMemStorage(), func(jb *apidef.UpstreamOAuthJWTBearer) {
			jb.ExpiresIn = tyktime.ReadableDuration(90 * time.Second)
			jb.Header = apidef.AuthSource{Enabled: true, Name: "X-Upstream-Auth"}
		})

		headers, _, err := processAndFill(t, m)
		require.NoError(t, err)
		assert.Equal(t, "Bearer sf-access-token", headers.Get("X-Upstream-Auth"))
		assert.Empty(t, headers.Get("Authorization"))

		iat, exp := idp.claims["iat"].(float64), idp.claims["exp"].(float64)
		assert.Equal(t, float64(90), exp-iat)
	})
}

func TestJWTBearer_CacheReuseAndRenewal(t *testing.T) {
	cert, pub := newTestRSACert(t)
	idp := newMockIdP(t, pub, func(w http.ResponseWriter, call int32) {
		writeTokenResponse(t, w, fmt.Sprintf("token-%d", call), 600)
	})

	store := newMemStorage()
	m := newJWTBearerMiddleware(idp.URL, &mockBaseMiddleware{cert: cert}, store, nil)

	for i := 0; i < 3; i++ {
		headers, _, err := processAndFill(t, m)
		require.NoError(t, err)
		assert.Equal(t, "Bearer token-1", headers.Get("Authorization"))
	}
	assert.Equal(t, 1, idp.callCount(), "token is reused from cache")
	assert.Equal(t, 1, store.setCalls)

	for _, ttl := range store.ttls {
		assert.InDelta(t, 600, ttl, 2, "cache TTL follows expires_in")
	}

	store.expire()

	headers, _, err := processAndFill(t, m)
	require.NoError(t, err)
	assert.Equal(t, "Bearer token-2", headers.Get("Authorization"), "new JWT is exchanged after expiry")
	assert.Equal(t, 2, idp.callCount())
}

func TestJWTBearer_TokenWithoutExpiresInUsesDefaultTTL(t *testing.T) {
	cert, pub := newTestRSACert(t)
	idp := newMockIdP(t, pub, func(w http.ResponseWriter, _ int32) {
		writeTokenResponse(t, w, "salesforce-style-token", 0)
	})

	store := newMemStorage()
	m := newJWTBearerMiddleware(idp.URL, &mockBaseMiddleware{cert: cert}, store, nil)

	_, _, err := processAndFill(t, m)
	require.NoError(t, err)
	require.Len(t, store.ttls, 1)
	for _, ttl := range store.ttls {
		assert.InDelta(t, defaultJWTBearerTokenTTL.Seconds(), ttl, 2)
	}
}

func TestJWTBearer_SigningKeyUnavailable(t *testing.T) {
	rsaCert, _ := newTestRSACert(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testCases := []struct {
		name    string
		cert    *tls.Certificate
		certErr error
	}{
		{name: "certificate not found", certErr: errors.New(`certificate "cert-id" not found or has no private key`)},
		{name: "nil certificate", cert: nil},
		{name: "no private key", cert: &tls.Certificate{Certificate: rsaCert.Certificate}},
		{name: "non RSA private key", cert: &tls.Certificate{Certificate: rsaCert.Certificate, PrivateKey: ecKey}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newMockIdP(t, nil, func(w http.ResponseWriter, _ int32) {
				writeTokenResponse(t, w, "should-not-be-issued", 3600)
			})

			base := &mockBaseMiddleware{cert: tc.cert, certErr: tc.certErr}
			base.On("FireEvent", event.UpstreamOAuthError, mock.Anything).Return()
			store := newMemStorage()
			m := newJWTBearerMiddleware(idp.URL, base, store, nil)

			_, code, err := processAndFill(t, m)
			require.Error(t, err)
			assert.Equal(t, http.StatusInternalServerError, code)

			var signErr *JWTBearerSigningError
			require.ErrorAs(t, err, &signErr)
			assert.Equal(t, jwtTestCertID, signErr.CertID)

			assert.Zero(t, idp.callCount(), "IdP must not be called")
			assert.Zero(t, store.setCalls, "nothing is cached")
			base.AssertCalled(t, "FireEvent", event.UpstreamOAuthError, mock.Anything)
		})
	}
}

func TestJWTBearer_IdPRejection(t *testing.T) {
	cert, pub := newTestRSACert(t)

	testCases := []struct {
		name       string
		respond    func(t *testing.T, w http.ResponseWriter)
		wantStatus int
		wantIdPErr string
	}{
		{
			name: "401 invalid_client",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusUnauthorized, "invalid_client")
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "invalid_client",
		},
		{
			name: "403 status wins over error code",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusForbidden, "invalid_grant")
			},
			wantStatus: http.StatusForbidden,
			wantIdPErr: "invalid_grant",
		},
		{
			name: "400 invalid_grant maps to 401",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusBadRequest, "invalid_grant")
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "invalid_grant",
		},
		{
			name: "400 unauthorized_client",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusBadRequest, "unauthorized_client")
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "unauthorized_client",
		},
		{
			name: "400 invalid_client_metadata",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusBadRequest, "invalid_client_metadata")
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "invalid_client_metadata",
		},
		{
			name: "400 access_denied maps to 403",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusBadRequest, "access_denied")
			},
			wantStatus: http.StatusForbidden,
			wantIdPErr: "access_denied",
		},
		{
			name: "unknown IdP error maps to 401",
			respond: func(t *testing.T, w http.ResponseWriter) {
				writeOAuthError(t, w, http.StatusInternalServerError, "server_error")
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "server_error",
		},
		{
			name: "non JSON error body maps to 401",
			respond: func(t *testing.T, w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte("bad request"))
				assert.NoError(t, err)
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "unknown",
		},
		{
			name: "success without access_token maps to 401",
			respond: func(t *testing.T, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{"token_type":"Bearer"}`))
				assert.NoError(t, err)
			},
			wantStatus: http.StatusUnauthorized,
			wantIdPErr: "invalid_token_response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newMockIdP(t, pub, func(w http.ResponseWriter, _ int32) { tc.respond(t, w) })

			base := &mockBaseMiddleware{cert: cert}
			base.On("FireEvent", event.UpstreamOAuthError, mock.Anything).Return()
			store := newMemStorage()
			m := newJWTBearerMiddleware(idp.URL, base, store, nil)

			headers, code, err := processAndFill(t, m)
			require.Error(t, err)
			assert.Nil(t, headers, "upstream auth is not set")
			assert.Equal(t, tc.wantStatus, code)

			var idpErr *JWTBearerIdPError
			require.ErrorAs(t, err, &idpErr)
			assert.Equal(t, tc.wantIdPErr, idpErr.IdPError)

			assert.Equal(t, 1, idp.callCount())
			assert.Zero(t, store.setCalls, "rejections are not cached")
			base.AssertCalled(t, "FireEvent", event.UpstreamOAuthError, mock.Anything)
		})
	}
}

func TestJWTBearer_IdPUnreachableIsServerError(t *testing.T) {
	cert, _ := newTestRSACert(t)
	idp := httptest.NewServer(http.NotFoundHandler())
	tokenURL := idp.URL
	idp.Close()

	base := &mockBaseMiddleware{cert: cert}
	base.On("FireEvent", event.UpstreamOAuthError, mock.Anything).Return()
	store := newMemStorage()
	m := newJWTBearerMiddleware(tokenURL, base, store, nil)

	_, code, err := processAndFill(t, m)
	require.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Zero(t, store.setCalls)
}

func TestExistingGrantsKeepServerErrorOnTokenFailure(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeOAuthError(t, w, http.StatusUnauthorized, "invalid_client")
	}))
	defer idp.Close()

	for _, authType := range []string{ClientCredentialsAuthorizeType, PasswordAuthorizeType} {
		t.Run(authType, func(t *testing.T) {
			base := &mockBaseMiddleware{}
			base.On("FireEvent", event.UpstreamOAuthError, mock.Anything).Return()
			spec := model.MergedAPI{APIDefinition: &apidef.APIDefinition{
				APIID: "api",
				UpstreamAuth: apidef.UpstreamAuth{
					Enabled: true,
					OAuth: apidef.UpstreamOAuth{
						Enabled:               true,
						AllowedAuthorizeTypes: []string{authType},
						ClientCredentials: apidef.ClientCredentials{
							ClientAuthData: apidef.ClientAuthData{ClientID: "id", ClientSecret: "secret"},
							TokenURL:       idp.URL,
						},
						PasswordAuthentication: apidef.PasswordAuthentication{
							ClientAuthData: apidef.ClientAuthData{ClientID: "id", ClientSecret: "secret"},
							Username:       "u",
							Password:       "p",
							TokenURL:       idp.URL,
						},
					},
				},
			}}
			store := newMemStorage()
			m := NewMiddleware(&mockGateway{config: config.Config{Secret: "s"}}, base, spec, store, store, store)

			err, code := m.ProcessRequest(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), nil)
			require.Error(t, err)
			assert.Equal(t, http.StatusInternalServerError, code)
		})
	}
}

func TestNewOAuthHeaderProvider_JWTBearer(t *testing.T) {
	p, err := NewOAuthHeaderProvider(apidef.UpstreamOAuth{
		Enabled:               true,
		AllowedAuthorizeTypes: []string{apidef.OAuthAuthorizationTypeJWTBearer},
	})
	require.NoError(t, err)
	assert.IsType(t, &JWTBearerOAuthProvider{}, p)
}

func TestGenerateJWTBearerCacheKey(t *testing.T) {
	base := apidef.UpstreamOAuth{JWTBearer: apidef.UpstreamOAuthJWTBearer{
		TokenURL: "https://idp/token",
		CertID:   "cert",
		Issuer:   "iss",
		Subject:  "sub",
		Audience: "aud",
	}}
	key := generateJWTBearerCacheKey(base, "api")
	assert.Equal(t, key, generateJWTBearerCacheKey(base, "api"), "deterministic")
	assert.Len(t, key, 64, "hashed")

	mutations := map[string]func(*apidef.UpstreamOAuthJWTBearer){
		"tokenUrl": func(j *apidef.UpstreamOAuthJWTBearer) { j.TokenURL = "https://other/token" },
		"certId":   func(j *apidef.UpstreamOAuthJWTBearer) { j.CertID = "other" },
		"issuer":   func(j *apidef.UpstreamOAuthJWTBearer) { j.Issuer = "other" },
		"subject":  func(j *apidef.UpstreamOAuthJWTBearer) { j.Subject = "other" },
		"audience": func(j *apidef.UpstreamOAuthJWTBearer) { j.Audience = "other" },
	}
	for name, mutate := range mutations {
		cfg := base
		mutate(&cfg.JWTBearer)
		assert.NotEqual(t, key, generateJWTBearerCacheKey(cfg, "api"), name)
	}
	assert.NotEqual(t, key, generateJWTBearerCacheKey(base, "other-api"), "apiId")

	t.Run("separator in values does not collide", func(t *testing.T) {
		left := base
		left.JWTBearer.Issuer = "A|B"
		left.JWTBearer.Subject = "C"

		right := base
		right.JWTBearer.Issuer = "A"
		right.JWTBearer.Subject = "B|C"

		leftKey := generateJWTBearerCacheKey(left, "api")
		rightKey := generateJWTBearerCacheKey(right, "api")
		assert.NotEqual(t, leftKey, rightKey)
		assert.Regexp(t, `^[0-9a-f]{64}$`, leftKey)
		assert.Regexp(t, `^[0-9a-f]{64}$`, rightKey)
	})
}

func TestDefaultJWTBearerHTTPClient_HasTimeout(t *testing.T) {
	require.NotNil(t, defaultJWTBearerHTTPClient)
	assert.NotSame(t, http.DefaultClient, defaultJWTBearerHTTPClient)
	assert.Equal(t, 15*time.Second, defaultJWTBearerHTTPClient.Timeout)
}
