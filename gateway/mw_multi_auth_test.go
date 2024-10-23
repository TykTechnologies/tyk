package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestMultiAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("OR authentication", func(t *testing.T) {

		apiId := "test-multi-auth-api"
		// Create test keys
		session := CreateStandardSession()
		session.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: apiId,
			Versions: []string{"v1"},
		}}

		// Create a JWT user
		jwtToken := CreateJWTSession("jwt-user", session)

		// Create a Basic Auth user
		basicAuthUser := CreateStandardSession()
		basicAuthKey := generateBasicAuthKey(ts.Gw, "basic-user", "password123", basicAuthUser)
		log.Println(basicAuthKey)

		buildAPI := func(spec *APISpec) {
			spec.IsOAS = true
			spec.APIID = apiId
			spec.Name = "test-multi-auth-api"
			spec.OrgID = "default"
			spec.Proxy.ListenPath = "/oas-api"

			tykExtension := &oas.XTykAPIGateway{
				Info: oas.Info{
					Name: apiId,
					ID:   apiId, // Match the APIID in session
					State: oas.State{
						Active: true,
					},

				},
				Upstream: oas.Upstream{
					URL: TestHttpAny,
				},
				Server: oas.Server{
					Authentication: &oas.Authentication{
						Enabled:           true,
						MultiSchemeEnabled: true,
						Strategy:          oas.AuthStrategyAny,
						SecuritySchemes: oas.SecuritySchemes{
							"jwt": &oas.JWT{
								Enabled:       true,
								SigningMethod: "HS256",
							},
							"basic": &oas.Basic{
								Enabled:        true,
								DisableCaching: false,
							},
						},
					},
					ListenPath: oas.ListenPath{
						Value: "/oas-api/",
						Strip: true,
					},
				},
			}

			spec.OAS = oas.OAS{
				T: openapi3.T{
					OpenAPI: "3.0.3",
					Info: &openapi3.Info{
						Title:   "Test API",
						Version: "1.0",
					},
					Paths: openapi3.Paths{
                        "/multi-auth": &openapi3.PathItem{
                            Get: &openapi3.Operation{
                                Security: &openapi3.SecurityRequirements{
                                    {"jwt": []string{}},
                                    {"basic": []string{}},
                                },
                                Responses: openapi3.Responses{
                                    "200": &openapi3.ResponseRef{
                                        Value: &openapi3.Response{
                                            Description: getStrPointer("Hello World"),
                                        },
                                    },
                                },
                            },
                        },
                    },
					Security: openapi3.SecurityRequirements{
						{"jwt": []string{}},
						{"basic": []string{}},
					},
					Components: &openapi3.Components{
						SecuritySchemes: openapi3.SecuritySchemes{
							"jwt": {
								Value: &openapi3.SecurityScheme{
									Type:         "http",
									Scheme:       "bearer",
									BearerFormat: "JWT",
								},
							},
							"basic": {
								Value: &openapi3.SecurityScheme{
									Type:   "http",
									Scheme: "basic",
								},
							},
						},
					},
				},
			}

			spec.OAS.SetTykExtension(tykExtension)
		}

		api := ts.Gw.BuildAndLoadAPI(buildAPI)[0]
		log.Println(api)

		   // Verify API was loaded correctly
		if t.Failed() {
            t.Fatalf("API failed to load. APIID: %v, ListenPath: %v", api.APIID, api.Proxy.ListenPath)
        }

		// Print loaded APIs for debugging
		loadedAPI := ts.Gw.getApiSpec(apiId)
		t.Logf("Loaded API - ID: %v, Name: %v, Listen Path: %v", 
			loadedAPI.APIID, 
			loadedAPI.Name, 
			loadedAPI.Proxy.ListenPath)
		

		// Test JWT authentication
		t.Run("succeeds with valid JWT", func(t *testing.T) {
			authHeader := map[string]string{
				"Authorization": "Bearer " + jwtToken,
			}

			ts.Run(t, []test.TestCase{
				{
					Path:    "/oas-api/multi-auth",
					Method:  http.MethodGet,
					Headers: authHeader,
					Code:    http.StatusOK,
				},
			}...)
		})

		// Test Basic authentication
		t.Run("succeeds with valid Basic Auth", func(t *testing.T) {
			credentials := base64.StdEncoding.EncodeToString([]byte("basic-user:password123"))
			authHeader := map[string]string{
				"Authorization": "Basic " + credentials,
			}

			ts.Run(t, []test.TestCase{
				{
					Path:    "/oas-api/multi-auth",
					Method:  http.MethodGet,
					Headers: authHeader,
					Code:    http.StatusOK,
				},
			}...)
		})

		// Test failed authentication
		t.Run("fails with invalid credentials", func(t *testing.T) {
			// Test with invalid JWT
			invalidJWTHeader := map[string]string{
				"Authorization": "Bearer invalid-token",
			}
			ts.Run(t, []test.TestCase{
				{
					Path:    "/oas-api/multi-auth",
					Method:  http.MethodGet,
					Headers: invalidJWTHeader,
					Code:    http.StatusUnauthorized,
				},
			}...)

			// Test with invalid Basic Auth
			invalidCredentials := base64.StdEncoding.EncodeToString([]byte("wrong:credentials"))
			invalidBasicHeader := map[string]string{
				"Authorization": "Basic " + invalidCredentials,
			}
			ts.Run(t, []test.TestCase{
				{
					Path:    "/oas-api/multi-auth",
					Method:  http.MethodGet,
					Headers: invalidBasicHeader,
					Code:    http.StatusUnauthorized,
				},
			}...)

			// Test with no auth
			ts.Run(t, []test.TestCase{
				{
					Path:   "/oas-api/multi-auth",
					Method: http.MethodGet,
					Code:   http.StatusUnauthorized,
				},
			}...)
		})
	})
}

// Helper function to generate a basic auth key
func generateBasicAuthKey(gw *Gateway, username, password string, session *user.SessionState) string {
	key := username + ":" + password
	keyName := base64.StdEncoding.EncodeToString([]byte(key))
	gw.GlobalSessionManager.UpdateSession(keyName, session, 60, false)
	return keyName
}

// Helper function to create a JWT session
func CreateJWTSession(userID string, session *user.SessionState) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("secret"))
	return signedToken
}
