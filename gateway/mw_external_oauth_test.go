package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
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
		flush := func() {
			if externalOAuthJWKCache != nil {
				externalOAuthJWKCache.Flush()
			}
		}

		t.Run("Direct JWK URL", func(t *testing.T) {
			t.Run("valid jwk url", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.Source = testHttpJWK
				_ = ts.Gw.LoadAPI(spec)
				t.Run("empty cache", func(t *testing.T) {
					flush()
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
		BaseMiddleware{
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
		externalOAuthIntrospectionCache.DeleteAllKeys()
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/get", Headers: headers, BodyMatch: "access token is not valid", Code: http.StatusUnauthorized},
		}...)

		t.Run("expired", func(t *testing.T) {
			externalOAuthIntrospectionCache.DeleteAllKeys()

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
