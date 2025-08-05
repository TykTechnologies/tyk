package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// Test matching the user's specific OAS configuration
func createUserOASSpec() string {
	return `{
		"openapi": "3.0.3",
		"info": {
			"title": "MyOAS",
			"version": "1.0.0"
		},
		"servers": [
			{
				"url": "http://localhost:8181/myoas/"
			}
	],
		"security": [
			{
				"basicAuth": [],
				"authToken": []
			},
			{
				"basicAuth": []
			}
	],
		"paths": {
			"/get": {
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
				"basicAuth": {
					"type": "http",
					"scheme": "basic"
				},
				"authToken": {
					"type": "apiKey",
					"in": "header",
					"name": "Authorization"
				}
		}
	},
		"x-tyk-api-gateway": {
			"info": {
				"name": "MyOAS",
				"id": "myoas-test",
				"dbId": "688b4e3395014f6fd790fa2e",
				"orgId": "686bace095014f355261567d",
				"state": {
					"active": true,
					"internal": false
				}
		},
			"upstream": {
				"url": "` + TestHttpAny + `"
			},
			"server": {
				"listenPath": {
					"value": "/myoas/",
					"strip": true
				},
				"authentication": {
					"enabled": true,
					"securitySchemes": {
						"authToken": {
							"enabled": true
						},
						"basicAuth": {
							"enabled": true,
							"header": {
								"enabled": true,
								"name": "Authorization"
							}
					}
				}
			}
		},
			"middleware": {
				"global": {
					"contextVariables": {
						"enabled": true
					},
					"trafficLogs": {
						"enabled": true
					}
			}
		}
	}
}`
}

func createUserBasicAuthSession() *user.SessionState {
	session := user.NewSessionState()
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.BasicAuthData.Password = "testing"
	session.AccessRights = map[string]user.AccessDefinition{"myoas-test": {APIName: "MyOAS", APIID: "myoas-test", Versions: []string{"Default"}}}
	return session
}

func TestUserScenario_BasicAuth_Only_Success(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Load the user's exact OAS configuration
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(createUserOASSpec()))
	if err != nil {
		t.Fatal("Failed to load OAS spec:", err)
	}

	oasAPI := oas.OAS{T: *doc}
	oasAPI.SetTykExtension(oasAPI.GetTykExtension())
	
	// Extract to APIDefinition to trigger authentication processing
	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIDefinition = &def
		spec.IsOAS = true
		spec.OAS = oasAPI
	})

	// Create basic auth session for "testing@testing.com:testing"
	username := "testing@testing.com"
	password := "testing"
	session := createUserBasicAuthSession()
	// For basic auth, use the username directly as the key
	err = ts.Gw.GlobalSessionManager.UpdateSession(username, session, 60, false)
	if err != nil {
		t.Fatal("Could not update session:", err)
	}

	// Encode basic auth credentials (dGVzdGluZ0B0ZXN0aW5nLmNvbTp0ZXN0aW5n)
	toEncode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(toEncode))
	expectedEncoded := "dGVzdGluZ0B0ZXN0aW5nLmNvbTp0ZXN0aW5n"
	
	if encodedPass != expectedEncoded {
		t.Logf("Expected encoded: %s", expectedEncoded)
		t.Logf("Got encoded: %s", encodedPass)
	}

	t.Logf("Testing with Authorization: Basic %s", encodedPass)

	// Test request with basic auth only (should succeed with OR logic - second requirement)
	ts.Run(t, []test.TestCase{
		{
			Path:      "/myoas/get",
			Code:      http.StatusOK,
			Headers:   map[string]string{"Authorization": fmt.Sprintf("Basic %s", encodedPass)},
			BodyMatch: `"Url":"/get"`, // TestHttpAny response should contain the path
		},
	}...)
}

func TestUserScenario_Debug_SecurityRequirements(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	var spec *APISpec
	
	// Load the user's exact OAS configuration and inspect it
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(createUserOASSpec()))
	if err != nil {
		t.Fatal("Failed to load OAS spec:", err)
	}

	oasAPI := oas.OAS{T: *doc}
	
	// Set the Tyk extension properly
	oasAPI.SetTykExtension(oasAPI.GetTykExtension())
	
	// This is the crucial step - ExtractTo processes the OAS and populates authentication
	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	
	ts.Gw.BuildAndLoadAPI(func(s *APISpec) {
		s.APIDefinition = &def
		s.IsOAS = true
		s.OAS = oasAPI
		spec = s
		
t.Logf("Number of security requirements: %d", len(s.OAS.Security))
		for i, req := range s.OAS.Security {
			t.Logf("Security requirement %d: %+v", i, req)
		}

		// Check if MultiAuth is enabled
		if auth := s.OAS.GetTykExtension().Server.Authentication; auth != nil {
			if auth.MultiAuth != nil {
				t.Logf("MultiAuth enabled: %t", auth.MultiAuth.Enabled)
				t.Logf("MultiAuth requirements: %+v", auth.MultiAuth.Requirements)
			} else {
				t.Log("MultiAuth is nil")
			}
	} else {
			t.Log("Authentication is nil")
		}
})
	
	// Test the isMultiAuthEnabled function
	if ts.Gw.isMultiAuthEnabled(spec) {
		t.Log("isMultiAuthEnabled returned true")
	} else {
		t.Log("isMultiAuthEnabled returned false")
	}
}
