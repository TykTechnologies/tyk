package gateway

import (
	"encoding/base64"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"testing"
	"time"
)

func TestExternalOAuth_JWT(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("JWT HMAC", func(t *testing.T) {
		_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
		})

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

	t.Run("time validation", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
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
		})[0]

		t.Run("expires at", func(t *testing.T) {
			jwtAuthHeaderGen := func(skew time.Duration) map[string]string {
				jwtToken := CreateJWKToken(func(t *jwt.Token) {
					t.Claims.(jwt.MapClaims)["user_id"] = "user123"
					t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(skew).Unix()
				})

				return map[string]string{"authorization": jwtToken}
			}

			t.Run("after now - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.ExpiresAtValidationSkew = 0
				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
				})
			})

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

			t.Run("before now with skew - valid", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.ExpiresAtValidationSkew = 1000
				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
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

			t.Run("before now - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 0

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
				})
			})

			t.Run("after now, no skew - invalid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 0

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers:   jwtAuthHeaderGen(+time.Minute),
					Code:      http.StatusUnauthorized,
					BodyMatch: "key not authorized: token used before issued",
				})
			})

			t.Run("after now with large skew - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 1000
				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(+time.Second),
					Code:    http.StatusOK,
				})
			})

			t.Run("before now, add skew - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 2
				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(-3 * time.Second), Code: http.StatusOK,
				})
			})

			t.Run("after now, add skew - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.IssuedAtValidationSkew = 1

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
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

			t.Run("not before now - valid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.NotBeforeValidationSkew = 0

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(-time.Second), Code: http.StatusOK,
				})
			})

			t.Run("after now - invalid jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.NotBeforeValidationSkew = 0

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers:   jwtAuthHeaderGen(+time.Second),
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

			t.Run("after now with huge skew --valid_jwt", func(t *testing.T) {
				spec.ExternalOAuth.Providers[0].JWT.NotBeforeValidationSkew = 1000 // This value is so high that it's actually similar to disabling the claim.

				_ = ts.Gw.LoadAPI(spec)

				_, _ = ts.Run(t, test.TestCase{
					Headers: jwtAuthHeaderGen(+time.Second), Code: http.StatusOK,
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
			spec.ExternalOAuth.Providers[0].JWT.Source = testHttpJWK
			_ = ts.Gw.LoadAPI(spec)
			flush()
			_, _ = ts.Run(t, test.TestCase{
				Headers: authHeaders, Code: http.StatusOK,
			})
		})

		t.Run("Base64", func(t *testing.T) {
			spec.ExternalOAuth.Providers[0].JWT.Source = base64.StdEncoding.EncodeToString([]byte(testHttpJWK))
			_ = ts.Gw.LoadAPI(spec)
			flush()
			_, _ = ts.Run(t, test.TestCase{
				Headers: authHeaders, Code: http.StatusOK,
			})
		})
	})
}
