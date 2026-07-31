package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
)

func TestExternalOAuth_JWT(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("JWT HMAC", func(t *testing.T) {
		spec := BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.ExternalOAuth = apidef.ExternalOAuth{
				Enabled: true,
				Providers: []apidef.Provider{
					{
						JWT: apidef.JWTValidation{
							Enabled:       true,
							SigningMethod: HMACSign,
							Source:        base64.StdEncoding.EncodeToString([]byte(jwtSecret)),
						},
					},
				},
			}
			spec.Proxy.ListenPath = "/"
		})[0]

		_ = ts.Gw.LoadAPI(spec)

		t.Run("base64 encoded static secret - success", func(t *testing.T) {
			jwtToken := createJWKTokenHMAC(func(t *jwt.Token) {
				t.Claims.(jwt.MapClaims)["sub"] = "bar"
				t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
			})

			authHeaders := map[string]string{"authorization": jwtToken}
			_, _ = ts.Run(t, test.TestCase{
				Headers: authHeaders, Code: http.StatusOK,
			})
		})

		t.Run("base64 encoded static secret - failure", func(t *testing.T) {
			jwtToken := createJWKTokenHMAC(func(t *jwt.Token) {
				t.Claims.(jwt.MapClaims)["sub"] = "bar"
				t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
			})

			t.Run("invalid signature", func(t *testing.T) {
				token := jwtToken + "blah"
				authHeaders := map[string]string{"authorization": token}
				_, _ = ts.Run(t, test.TestCase{
					Headers: authHeaders, Code: http.StatusUnauthorized,
				})
			})

			t.Run("invalid token", func(t *testing.T) {
				token := "blah"
				authHeaders := map[string]string{"authorization": token}
				_, _ = ts.Run(t, test.TestCase{
					Headers: authHeaders, Code: http.StatusUnauthorized,
				})
			})

			t.Run("configured HMAC, signed RSA", func(t *testing.T) {
				token := CreateJWKToken(func(t *jwt.Token) {
					t.Claims.(jwt.MapClaims)["foo"] = "bar"
					t.Claims.(jwt.MapClaims)["user_id"] = "user"
				})

				authHeaders := map[string]string{"authorization": token}
				_, _ = ts.Run(t, test.TestCase{
					Headers: authHeaders, Code: http.StatusInternalServerError,
				})
			})

		})
	})

	t.Run("JWT RSA with JWK", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.ExternalOAuth = apidef.ExternalOAuth{
				Enabled: true,
				Providers: []apidef.Provider{
					{
						JWT: apidef.JWTValidation{
							Enabled:           true,
							SigningMethod:     RSASign,
							Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
							IdentityBaseField: "user_id",
						},
					},
				},
			}
			spec.Proxy.ListenPath = "/"
		})[0]

		t.Run("with skew", func(t *testing.T) {
			t.Run("expires at", func(t *testing.T) {
				jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
					jwtToken := CreateJWKToken(func(t *jwt.Token) {
						t.Claims.(jwt.MapClaims)["user_id"] = "user123"
						t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(skew).Unix()
					})

					return map[string]string{"authorization": jwtToken}
				}

				t.Run("after now - add skew", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.ExpiresAtValidationSkew = 1
					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
					})
				})

				t.Run("before now - invalid jwt", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.ExpiresAtValidationSkew = 0
					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers:   jwtAuthHeaderGen(-time.Second),
						Code:      http.StatusUnauthorized,
						BodyMatch: "key not authorized: token has expired",
					})
				})
			})

			t.Run("issued at", func(t *testing.T) {
				jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
					jwtToken := CreateJWKToken(func(t *jwt.Token) {
						t.Claims.(jwt.MapClaims)["user_id"] = "user123"
						t.Claims.(jwt.MapClaims)["iat"] = time.Now().Add(skew).Unix()
					})

					return map[string]string{"authorization": jwtToken}
				}

				t.Run("after now, no skew - invalid jwt", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 1

					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers:   jwtAuthHeaderGen(+time.Minute),
						Code:      http.StatusUnauthorized,
						BodyMatch: "key not authorized: token used before issued",
					})
				})

				t.Run("before now, add skew - valid jwt", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 2
					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers: jwtAuthHeaderGen(-3 * time.Second), Code: http.StatusOK,
					})
				})
			})

			t.Run("not before", func(t *testing.T) {
				jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
					jwtToken := CreateJWKToken(func(t *jwt.Token) {
						t.Claims.(jwt.MapClaims)["user_id"] = "user123"
						t.Claims.(jwt.MapClaims)["nbf"] = time.Now().Add(skew).Unix()
					})
					return map[string]string{"authorization": jwtToken}
				}

				t.Run("after now - invalid jwt", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.NotBeforeValidationSkew = 1

					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers:   jwtAuthHeaderGen(+time.Minute),
						Code:      http.StatusUnauthorized,
						BodyMatch: "key not authorized: token is not valid yet",
					})
				})

				t.Run("after now, add skew - valid jwt", func(t *testing.T) {
					spec.ExternalOAuth.Providers[0].JWT.NotBeforeValidationSkew = 1

					_ = ts.Gw.LoadAPI(spec)

					_, _ = ts.Run(t, test.TestCase{
						Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
					})
				})

			})
		})

		jwtToken := CreateJWKToken(func(t *jwt.Token) {
			t.Header["kid"] = "12345"
			t.Claims.(jwt.MapClaims)["foo"] = "bar"
			t.Claims.(jwt.MapClaims)["user_id"] = "user"
			t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour * 72).Unix()
		})

		authHeaders := map[string]string{"authorization": jwtToken}

		t.Run("Direct JWK URL", func(t *testing.T) {
			t.Run("valid jwk url", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.Source = testHttpJWK
				_ = ts.Gw.LoadAPI(spec)
				t.Run("empty cache", func(t *testing.T) {
					ts.Gw.jwkCache.Flush()
					_, _ = ts.Run(t, test.TestCase{
						Headers: authHeaders, Code: http.StatusOK,
					})
				})

				t.Run("with cache", func(t *testing.T) {
					_, _ = ts.Run(t, test.TestCase{
						Headers: authHeaders, Code: http.StatusOK,
					})
				})
			})

		})

	})
}

func TestGetSecretFromJWKOrConfig(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.ExternalOAuth = apidef.ExternalOAuth{
			Enabled: true,
			Providers: []apidef.Provider{
				{
					JWT: apidef.JWTValidation{
						Enabled:           true,
						IdentityBaseField: "user_id",
					},
				},
			},
		}
		spec.Proxy.ListenPath = "/"
	})[0]

	k := ExternalOAuthMiddleware{
		&BaseMiddleware{
			Gw:   ts.Gw,
			Spec: spec,
		},
	}

	t.Run("kid is not a string", func(t *testing.T) {
		spec.ExternalOAuth.Providers[0].JWT.SigningMethod = RSASign
		spec.ExternalOAuth.Providers[0].JWT.Source = testHttpJWK
		_, err := k.getSecretFromJWKOrConfig(23, spec.ExternalOAuth.Providers[0].JWT)
		assert.ErrorIs(t, err, ErrKIDNotAString)
	})

	t.Run("from config", func(t *testing.T) {
		spec.ExternalOAuth.Providers[0].JWT.SigningMethod = HMACSign
		spec.ExternalOAuth.Providers[0].JWT.Source = base64.StdEncoding.EncodeToString([]byte(jwtSecret))
		secret, err := k.getSecretFromJWKOrConfig(nil, spec.ExternalOAuth.Providers[0].JWT)
		assert.NoError(t, err)
		assert.Equal(t, jwtSecret, string(secret.([]byte)))
	})

	t.Run("invalid base64 encoded secret", func(t *testing.T) {
		spec.ExternalOAuth.Providers[0].JWT.SigningMethod = HMACSign
		spec.ExternalOAuth.Providers[0].JWT.Source = "invalid-secret"
		_, err := k.getSecretFromJWKOrConfig(nil, spec.ExternalOAuth.Providers[0].JWT)

		assert.Error(t, err)

	})

	t.Run("direct jwk url", func(t *testing.T) {
		spec.ExternalOAuth.Providers[0].JWT.Source = testHttpJWK
		spec.ExternalOAuth.Providers[0].JWT.SigningMethod = RSASign
		_, err := k.getSecretFromJWKOrConfig("12345", spec.ExternalOAuth.Providers[0].JWT)
		assert.NoError(t, err)

	})

	t.Run("base64 encoded jwk url", func(t *testing.T) {
		spec.ExternalOAuth.Providers[0].JWT.SigningMethod = HMACSign
		spec.ExternalOAuth.Providers[0].JWT.Source = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))
		_, err := k.getSecretFromJWKOrConfig("12345", spec.ExternalOAuth.Providers[0].JWT)
		assert.NoError(t, err)
	})
}

func TestExternalOAuthMiddleware_introspection(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		testClientID     = "test-client-id"
		testClientSecret = "test-client-secret"
		testAccessToken  = "test-access-token"
		user             = "furkan@example.com"
	)

	accessTokenActive := true
	exp := time.Now().Add(3 * time.Minute).Unix()

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, testAccessToken, r.FormValue("token"))
		assert.Equal(t, testClientID, r.FormValue("client_id"))
		assert.Equal(t, testClientSecret, r.FormValue("client_secret"))

		_, _ = w.Write([]byte(fmt.Sprintf(`{"active": %t,"username": "%s", "exp":%d}`, accessTokenActive, user, exp)))
	}))

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
		spec.ExternalOAuth.Enabled = true
		spec.ExternalOAuth.Providers = []apidef.Provider{
			{
				Introspection: apidef.Introspection{
					Enabled:           true,
					URL:               introspectionServer.URL,
					ClientID:          testClientID,
					ClientSecret:      testClientSecret,
					IdentityBaseField: "username",
				},
			},
		}
	})[0]

	headers := map[string]string{
		"Authorization": testAccessToken,
	}

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/get", BodyMatch: "authorization field missing", Code: http.StatusBadRequest},
		{Path: "/get", Headers: headers, BodyMatch: "/get", Code: http.StatusOK},
	}...)

	// deactivated access token should not be validated
	accessTokenActive = false
	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/get", Headers: headers, BodyMatch: "access token is not valid", Code: http.StatusUnauthorized},
	}...)

	t.Run("cache", func(t *testing.T) {
		t.Skip() // DeleteAllKeys interferes with other tests.

		api.ExternalOAuth.Providers[0].Introspection.Cache.Enabled = true
		api.ExternalOAuth.Providers[0].Introspection.Cache.Timeout = 0
		ts.Gw.LoadAPI(api)

		accessTokenActive = true
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: headers, BodyMatch: "/get", Code: http.StatusOK},
		}...)

		accessTokenActive = false
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: headers, BodyMatch: "/get", Code: http.StatusOK},
		}...)

		// invalidate cache
		externalOAuthIntrospectionCache.DeleteAllKeys() // exclusive
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: headers, BodyMatch: "access token is not valid", Code: http.StatusUnauthorized},
		}...)

		t.Run("expired", func(t *testing.T) {
			externalOAuthIntrospectionCache.DeleteAllKeys() // exclusive

			// normally for expired token, the introspection returns active false
			// this is to get rid of putting delay to wait until expiration
			accessTokenActive = true
			exp = time.Now().Add(-3 * time.Minute).Unix()
			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/get", Headers: headers, BodyMatch: "/get", Code: http.StatusOK},
				{Path: "/get", Headers: headers, BodyMatch: jwt.ErrTokenExpired.Error(), Code: http.StatusUnauthorized},
			}...)
		})
	})
}

// TestExternalOAuthMiddleware_MissingAuth_NoPRM_KeepsLegacy400 is a
// backward-compatibility regression guard. The external-OAuth
// missing-auth status changed from 400 to 401 only when PRM is enabled; an
// external-OAuth API without PRM must keep returning the historic 400 (and no
// WWW-Authenticate challenge), so existing consumers are not broken.
func TestExternalOAuthMiddleware_MissingAuth_NoPRM_KeepsLegacy400(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const (
		testClientID     = "test-client-id"
		testClientSecret = "test-client-secret"
	)

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"active": true, "username": "u"}`))
	}))
	defer introspectionServer.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/ext-oauth-no-prm/"
		spec.UseKeylessAccess = false
		spec.ExternalOAuth.Enabled = true
		spec.ExternalOAuth.Providers = []apidef.Provider{
			{
				Introspection: apidef.Introspection{
					Enabled:           true,
					URL:               introspectionServer.URL,
					ClientID:          testClientID,
					ClientSecret:      testClientSecret,
					IdentityBaseField: "username",
				},
			},
		}
	})

	// No Authorization header, no PRM configured -> legacy 400, no challenge.
	resp, _ := ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/ext-oauth-no-prm/get",
		BodyMatch: "authorization field missing",
		Code:      http.StatusBadRequest,
	})
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"),
		"no PRM configured means the legacy 400 is preserved with no WWW-Authenticate challenge")
}

// TestExternalOAuthMiddleware_PRM_MissingAuth_Returns401 covers the external-OAuth
// side of the 401 challenge. The middleware is a distinct code path from JWT, and
// the same PRM-gated 400 -> 401 change applies to it: a missing (or empty)
// credential on a PRM-enabled external-OAuth API must return 401 with the RFC 9728
// WWW-Authenticate challenge so an MCP client begins PRM discovery.
func TestExternalOAuthMiddleware_PRM_MissingAuth_Returns401(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	introspectionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"active": true, "username": "u"}`))
	}))
	defer introspectionServer.Close()

	oasDoc := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{Title: "Ext-OAuth PRM 401", Version: "1.0"},
			Paths:   openapi3.NewPaths(),
		},
	}
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info:     oas.Info{Name: "ext-oauth-prm-401", State: oas.State{Active: true}},
		Upstream: oas.Upstream{URL: "http://httpbin.org"},
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/ext-oauth-prm/", Strip: true},
			Authentication: &oas.Authentication{
				ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
					Enabled:              true,
					Resource:             "https://api.example.com",
					AuthorizationServers: []string{"https://auth.example.com"},
				},
			},
		},
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/ext-oauth-prm/"
		spec.UseKeylessAccess = false
		spec.IsOAS = true
		spec.OAS = oasDoc
		spec.ExternalOAuth.Enabled = true
		spec.ExternalOAuth.Providers = []apidef.Provider{
			{
				Introspection: apidef.Introspection{
					Enabled:           true,
					URL:               introspectionServer.URL,
					ClientID:          "test-client-id",
					ClientSecret:      "test-client-secret",
					IdentityBaseField: "username",
				},
			},
		}
	})

	assertChallenge := func(t *testing.T, resp *http.Response) {
		t.Helper()
		wwwAuth := resp.Header.Get(header.WWWAuthenticate)
		assert.Contains(t, wwwAuth, `Bearer realm="tyk"`)
		assert.Contains(t, wwwAuth, `resource_metadata=`)
		assert.Contains(t, wwwAuth, `.well-known/oauth-protected-resource`)
	}

	t.Run("missing Authorization header", func(t *testing.T) {
		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/ext-oauth-prm/get",
			Code:   http.StatusUnauthorized,
		})
		assertChallenge(t, resp)
	})

	t.Run("empty Authorization header", func(t *testing.T) {
		resp, _ := ts.Run(t, test.TestCase{
			Method:  http.MethodGet,
			Path:    "/ext-oauth-prm/get",
			Headers: map[string]string{"Authorization": ""},
			Code:    http.StatusUnauthorized,
		})
		assertChallenge(t, resp)
	})
}

func Test_isExpired(t *testing.T) {
	assert.False(t, isExpired(jwt.MapClaims{}))
	assert.False(t, isExpired(jwt.MapClaims{"exp": "not integer"}))

	claimsBuilder := func(d time.Duration) jwt.MapClaims {
		claimsStr := fmt.Sprintf(`{"exp":%d}`, time.Now().Add(d).Unix())
		var claims jwt.MapClaims
		_ = json.Unmarshal([]byte(claimsStr), &claims)
		return claims
	}

	assert.False(t, isExpired(claimsBuilder(10*time.Minute)))
	assert.True(t, isExpired(claimsBuilder(-10*time.Minute)))
}

func TestGetSecretFromJWKURL_FetchError_LogsError(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.jwkCache.Flush()

	logger, hook := logrustest.NewNullLogger()

	tsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("invalid-json-content"))
		assert.NoError(t, err)
	}))
	defer tsServer.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.ExternalOAuth = apidef.ExternalOAuth{
			Enabled: true,
			Providers: []apidef.Provider{
				{
					JWT: apidef.JWTValidation{
						Enabled:           true,
						IdentityBaseField: "user_id",
						SigningMethod:     RSASign,
						Source:            tsServer.URL,
					},
				},
			},
		}
	})[0]

	baseMw := &BaseMiddleware{Gw: ts.Gw, Spec: spec}
	baseMw.logger = logger.WithField("mw", "ExternalOAuthMiddleware")
	k := ExternalOAuthMiddleware{BaseMiddleware: baseMw}

	t.Run("Standard fetch failure triggers logJWKError", func(t *testing.T) {
		_, err := k.getSecretFromJWKOrConfig("any-kid", spec.ExternalOAuth.Providers[0].JWT)
		assert.Error(t, err)

		assert.NotEmpty(t, hook.Entries, "Expected a log entry but found none")
		lastLog := hook.LastEntry()
		assert.Equal(t, logrus.ErrorLevel, lastLog.Level)
		assert.Contains(t, lastLog.Message, "Invalid JWKS retrieved from endpoint")
		assert.Contains(t, lastLog.Message, tsServer.URL)
	})
}
