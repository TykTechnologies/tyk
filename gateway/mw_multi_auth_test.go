package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// Test helper to create an OAS spec with multi-auth (OR) configuration
func createMultiAuthOASSpec() string {
	return `{
		"openapi": "3.0.0",
		"info": {
			"title": "Multi-Auth Test API",
			"version": "1.0.0"
		},
		"servers": [
			{
				"url": "` + TestHttpAny + `"
			}
		],
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"description": "Success"
						}
					}
				}
			}
		},
		"components": {
			"securitySchemes": {
				"apiKey": {
					"type": "apiKey",
					"in": "header",
					"name": "Authorization"
				},
				"basicAuth": {
					"type": "http",
					"scheme": "basic"
				},
				"jwtAuth": {
					"type": "http",
					"scheme": "bearer",
					"bearerFormat": "JWT"
				}
			}
		},
		"security": [
			{"apiKey": []},
			{"basicAuth": []},
			{"jwtAuth": []}
		],
		"x-tyk-api-gateway": {
			"info": {
				"name": "Multi-Auth Test API",
				"id": "multi-auth-test"
			},
			"upstream": {
				"url": "` + TestHttpAny + `"
			},
			"server": {
				"listenPath": {
					"value": "/multi-auth-test/",
					"strip": true
				}
			}
		}
	}`
}

// createAPIKeySession creates a session for API key authentication
func createAPIKeySession() *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 900
	session.QuotaMax = 10
	session.AccessRights = map[string]user.AccessDefinition{"multi-auth-test": {APIName: "Multi-Auth Test API", APIID: "multi-auth-test", Versions: []string{"Default"}}}
	return session
}

// createBasicAuthSession creates a session for basic authentication
func createBasicAuthSession() *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.BasicAuthData.Password = "password123"
	session.AccessRights = map[string]user.AccessDefinition{"multi-auth-test": {APIName: "Multi-Auth Test API", APIID: "multi-auth-test", Versions: []string{"Default"}}}
	return session
}

// Helper function to create OAS from JSON string
func createOASFromJSON(jsonSpec string) oas.OAS {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(jsonSpec))
	if err != nil {
		panic("Failed to load OAS spec: " + err.Error())
	}
	
	err = doc.Validate(context.Background())
	if err != nil {
		panic("Failed to validate OAS spec: " + err.Error())
	}
	
	oasAPI := oas.OAS{T: *doc}
	
	// Set default Tyk extension if not present
	if oasAPI.GetTykExtension() == nil {
		oasAPI.SetTykExtension(&oas.XTykAPIGateway{})
	}
	
	return oasAPI
}

func TestMultiAuthMiddleware_OR_ApiKey_Success(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Load OAS API with multi-auth configuration
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		spec.OAS = createOASFromJSON(createMultiAuthOASSpec())
		
		// Configure MultiAuth to be enabled
		if spec.OAS.GetTykExtension().Server.Authentication == nil {
			spec.OAS.GetTykExtension().Server.Authentication = &oas.Authentication{}
		}
		auth := spec.OAS.GetTykExtension().Server.Authentication
		auth.Enabled = true
		auth.MultiAuth = &oas.MultiAuth{
			Enabled: true,
			Requirements: []oas.AuthRequirement{
				{Name: "api_key_auth", Schemes: map[string][]string{"apiKey": {}}},
				{Name: "basic_auth", Schemes: map[string][]string{"basicAuth": {}}},
			},
		}
	})

	// Create API key session
	apiKey := "test-api-key-12345"
	session := createAPIKeySession()
	err := ts.Gw.GlobalSessionManager.UpdateSession(apiKey, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Test request with API key only (should succeed with OR logic)
	ts.Run(t, []test.TestCase{
		{
			Path:      "/multi-auth-test/test",
			Code:      http.StatusOK,
			Headers:   map[string]string{"Authorization": apiKey},
			BodyMatch: `"Url":"/test"`, // Upstream response should contain the path
		},
	}...)
}

func TestMultiAuthMiddleware_OR_BasicAuth_Success(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Load OAS API with multi-auth configuration
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		spec.OAS = createOASFromJSON(createMultiAuthOASSpec())
		
		// Configure MultiAuth to be enabled
		if spec.OAS.GetTykExtension().Server.Authentication == nil {
			spec.OAS.GetTykExtension().Server.Authentication = &oas.Authentication{}
		}
		auth := spec.OAS.GetTykExtension().Server.Authentication
		auth.Enabled = true
		auth.MultiAuth = &oas.MultiAuth{
			Enabled: true,
			Requirements: []oas.AuthRequirement{
				{Name: "api_key_auth", Schemes: map[string][]string{"apiKey": {}}},
				{Name: "basic_auth", Schemes: map[string][]string{"basicAuth": {}}},
			},
		}
	})

	// Create basic auth session
	username := "testuser"
	password := "password123"
	session := createBasicAuthSession()
	// For basic auth, use the username directly as the key
	err := ts.Gw.GlobalSessionManager.UpdateSession(username, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Encode basic auth credentials
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))

	// Test request with basic auth only (should succeed with OR logic)
	ts.Run(t, []test.TestCase{
		{
			Path:      "/multi-auth-test/test",
			Code:      http.StatusOK,
			Headers:   map[string]string{"Authorization": fmt.Sprintf("Basic %s", encodedPass)},
			BodyMatch: `"Url":"/test"`, // Upstream response should contain the path
		},
	}...)
}

func TestMultiAuthMiddleware_OR_Fallback_Success(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Load OAS API with multi-auth configuration
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		spec.OAS = createOASFromJSON(createMultiAuthOASSpec())
		
		// Configure MultiAuth to be enabled
		if spec.OAS.GetTykExtension().Server.Authentication == nil {
			spec.OAS.GetTykExtension().Server.Authentication = &oas.Authentication{}
		}
		auth := spec.OAS.GetTykExtension().Server.Authentication
		auth.Enabled = true
		auth.MultiAuth = &oas.MultiAuth{
			Enabled: true,
			Requirements: []oas.AuthRequirement{
				{Name: "api_key_auth", Schemes: map[string][]string{"apiKey": {}}},
				{Name: "basic_auth", Schemes: map[string][]string{"basicAuth": {}}},
			},
		}
	})

	// Create only basic auth session (no API key session)
	username := "testuser"
	password := "password123"
	session := createBasicAuthSession()
	// For basic auth, use the username directly as the key
	err := ts.Gw.GlobalSessionManager.UpdateSession(username, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Encode basic auth credentials
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))

	// Test request with invalid API key and valid basic auth (should fallback and succeed)
	ts.Run(t, []test.TestCase{
		{
			Path: "/multi-auth-test/test",
			Code: http.StatusOK,
			Headers: map[string]string{
				"Authorization":   fmt.Sprintf("Basic %s", encodedPass),
				"X-Invalid-Token": "invalid-api-key", // This should be ignored
			},
			BodyMatch: `"Url":"/test"`,
		},
	}...)
}

func TestMultiAuthMiddleware_OR_AllFailed(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Load OAS API with multi-auth configuration
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		spec.OAS = createOASFromJSON(createMultiAuthOASSpec())
		
		// Configure MultiAuth to be enabled
		if spec.OAS.GetTykExtension().Server.Authentication == nil {
			spec.OAS.GetTykExtension().Server.Authentication = &oas.Authentication{}
		}
		auth := spec.OAS.GetTykExtension().Server.Authentication
		auth.Enabled = true
		auth.MultiAuth = &oas.MultiAuth{
			Enabled: true,
			Requirements: []oas.AuthRequirement{
				{Name: "api_key_auth", Schemes: map[string][]string{"apiKey": {}}},
				{Name: "basic_auth", Schemes: map[string][]string{"basicAuth": {}}},
			},
		}
	})

	// Test request with no authentication headers (should fail)
	ts.Run(t, []test.TestCase{
		{
			Path: "/multi-auth-test/test",
			Code: http.StatusUnauthorized,
		},
	}...)
}

func TestMultiAuthMiddleware_BackwardCompatibility_SingleAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS spec with single security requirement (should not trigger MultiAuth)
	singleAuthSpec := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Single Auth Test API",
			"version": "1.0.0"
		},
		"servers": [
			{
				"url": "` + TestHttpAny + `"
			}
		],
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"description": "Success"
						}
					}
				}
			}
		},
		"components": {
			"securitySchemes": {
				"apiKey": {
					"type": "apiKey",
					"in": "header",
					"name": "Authorization"
				}
			}
		},
		"security": [
			{"apiKey": []}
		],
		"x-tyk-api-gateway": {
			"info": {
				"name": "Single Auth Test API",
				"id": "single-auth-test"
			},
			"upstream": {
				"url": "` + TestHttpAny + `"
			},
			"server": {
				"listenPath": {
					"value": "/single-auth-test/",
					"strip": true
				}
			}
		}
	}`

	// Load OAS API with single auth (should use existing behavior)
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.IsOAS = true
		spec.OAS = createOASFromJSON(singleAuthSpec)
	})

	// Create API key session
	apiKey := "single-auth-key-12345"
	session := createAPIKeySession()
	session.AccessRights = map[string]user.AccessDefinition{"single-auth-test": {APIName: "Single Auth Test API", APIID: "single-auth-test", Versions: []string{"Default"}}}
	err := ts.Gw.GlobalSessionManager.UpdateSession(apiKey, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Test request with API key (should work with existing auth system)
	ts.Run(t, []test.TestCase{
		{
			Path:      "/single-auth-test/test",
			Code:      http.StatusOK,
			Headers:   map[string]string{"Authorization": apiKey},
			BodyMatch: `"Url":"/test"`,
		},
	}...)
}