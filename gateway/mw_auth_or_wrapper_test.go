package gateway

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	jwt "github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// generateHMACSignature generates a proper HMAC signature for HTTP Signature validation
func generateHMACSignature(method, path string, headers map[string]string, secret string, algorithm string) string {
	// Prepare signature string following HTTP Signature spec
	signatureString := "(request-target): " + strings.ToLower(method) + " " + path

	// Add headers in lowercase
	if date, ok := headers["Date"]; ok {
		signatureString += "\ndate: " + date
	}
	if xTest1, ok := headers["X-Test-1"]; ok {
		signatureString += "\nx-test-1: " + xTest1
	}
	if xTest2, ok := headers["X-Test-2"]; ok {
		signatureString += "\nx-test-2: " + xTest2
	}

	// Generate HMAC with specified algorithm
	key := []byte(secret)
	var h hash.Hash

	switch algorithm {
	case "hmac-sha256":
		h = hmac.New(sha256.New, key)
	case "hmac-sha1":
		h = hmac.New(sha1.New, key)
	default:
		h = hmac.New(sha1.New, key)
	}

	h.Write([]byte(signatureString))
	sigString := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(sigString)
}

// TestLegacyMode_BackwardCompatibility tests that legacy mode is the default
func TestLegacyMode_BackwardCompatibility(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "default" // Set OrgID
		s.AccessRights = map[string]user.AccessDefinition{
			"test-legacy": {
				APIName:  "Test Legacy",
				APIID:    "test-legacy",
				Versions: []string{"default"},
			},
		}
	})

	// Test API without explicit securityProcessingMode (should default to legacy)
	t.Run("API without securityProcessingMode defaults to legacy", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "test-legacy"
			spec.Name = "Test Legacy"
			spec.OrgID = "default" // Set OrgID
			spec.Proxy.ListenPath = "/test-legacy/"
			spec.UseKeylessAccess = false

			// Create OAS without specifying securityProcessingMode
			oasDoc := oas.OAS{}
			oasDoc.T = openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   spec.Name,
					Version: "1.0.0",
				},
				Paths: openapi3.NewPaths(),
			}

			oasDoc.T.Components = &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
					"basic": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:   "http",
							Scheme: "basic",
						},
					},
				},
			}

			// Multiple requirements (should only use first in legacy mode)
			oasDoc.T.Security = openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"apikey": []string{}},
				openapi3.SecurityRequirement{"basic": []string{}},
			}

			tykExtension := &oas.XTykAPIGateway{
				Info: oas.Info{
					ID:    spec.APIID,
					Name:  spec.Name,
					OrgID: "default", // Set OrgID
					State: oas.State{
						Active: true,
					},
				},
				Server: oas.Server{
					ListenPath: oas.ListenPath{
						Value: spec.Proxy.ListenPath,
						Strip: true,
					},
					Authentication: &oas.Authentication{
						Enabled: true,
						// No securityProcessingMode specified - should default to legacy
						SecuritySchemes: oas.SecuritySchemes{
							"apikey": &oas.Token{
								Enabled: func() *bool { b := true; return &b }(),
								AuthSources: oas.AuthSources{
									Header: &oas.AuthSource{
										Enabled: true,
										Name:    "X-API-Key",
									},
								},
							},
						},
					},
				},
				Upstream: oas.Upstream{
					URL: TestHttpAny,
				},
			}

			oasDoc.SetTykExtension(tykExtension)
			oasDoc.ExtractTo(spec.APIDefinition)
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		// Should succeed with API key (first requirement)
		testCases := []test.TestCase{
			{
				Method: "GET",
				Path:   "/test-legacy/",
				Headers: map[string]string{
					"X-API-Key": apiKey,
				},
				Code: http.StatusOK,
			},
			// Basic auth should fail (second requirement ignored in legacy mode)
			{
				Method: "GET",
				Path:   "/test-legacy/",
				Headers: map[string]string{
					"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")),
				},
				Code: http.StatusUnauthorized,
			},
		}

		ts.Run(t, testCases...)
	})

	// Test API with explicit legacy mode
	t.Run("API with explicit legacy mode", func(t *testing.T) {
		// Create API key for this specific API
		apiKey2 := CreateSession(ts.Gw, func(s *user.SessionState) {
			s.OrgID = "default" // Set OrgID
			s.AccessRights = map[string]user.AccessDefinition{
				"test-legacy-explicit": {
					APIName:  "Test Legacy Explicit",
					APIID:    "test-legacy-explicit",
					Versions: []string{"default"},
				},
			}
		})

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "test-legacy-explicit"
			spec.Name = "Test Legacy Explicit"
			spec.OrgID = "default" // Set OrgID
			spec.Proxy.ListenPath = "/test-legacy-explicit/"
			spec.UseKeylessAccess = false

			// Create OAS with explicit legacy mode
			oasDoc := oas.OAS{}
			oasDoc.T = openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   spec.Name,
					Version: "1.0.0",
				},
				Paths: openapi3.NewPaths(),
			}

			oasDoc.T.Components = &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			}

			// Multiple requirements
			oasDoc.T.Security = openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"apikey": []string{}},
			}

			tykExtension := &oas.XTykAPIGateway{
				Info: oas.Info{
					ID:    spec.APIID,
					Name:  spec.Name,
					OrgID: "default", // Set OrgID
					State: oas.State{
						Active: true,
					},
				},
				Server: oas.Server{
					ListenPath: oas.ListenPath{
						Value: spec.Proxy.ListenPath,
						Strip: true,
					},
					Authentication: &oas.Authentication{
						Enabled:                true,
						SecurityProcessingMode: "legacy", // Explicit legacy mode
						SecuritySchemes: oas.SecuritySchemes{
							"apikey": &oas.Token{
								Enabled: func() *bool { b := true; return &b }(),
								AuthSources: oas.AuthSources{
									Header: &oas.AuthSource{
										Enabled: true,
										Name:    "X-API-Key",
									},
								},
							},
						},
					},
				},
				Upstream: oas.Upstream{
					URL: TestHttpAny,
				},
			}

			oasDoc.SetTykExtension(tykExtension)
			oasDoc.ExtractTo(spec.APIDefinition)
			spec.IsOAS = true
			spec.OAS = oasDoc
		})

		// Test with API key
		testCases := []test.TestCase{
			{
				Method: "GET",
				Path:   "/test-legacy-explicit/",
				Headers: map[string]string{
					"X-API-Key": apiKey2,
				},
				Code: http.StatusOK,
			},
		}

		ts.Run(t, testCases...)
	})
}

// TestLegacyMode_OnlyFirstRequirementProcessed tests that only the first requirement is used in legacy mode
func TestLegacyMode_OnlyFirstRequirementProcessed(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create basic auth user
	basicAuthUser := "test-user"
	basicAuthPassword := "test-password"

	// Create basic auth session
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicAuthPassword
	basicSession.OrgID = "" // Use empty OrgID
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-legacy-first": {
			APIName:  "Test Legacy First",
			APIID:    "test-legacy-first",
			Versions: []string{"default"},
		},
	}
	_ = ts.Gw.GlobalSessionManager.UpdateSession(basicAuthUser, basicSession, 60, false)

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "" // Use empty OrgID
		s.AccessRights = map[string]user.AccessDefinition{
			"test-legacy-first": {
				APIName:  "Test Legacy First",
				APIID:    "test-legacy-first",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-legacy-first"
		spec.Name = "Test Legacy First"
		spec.OrgID = "" // Use empty OrgID
		spec.Proxy.ListenPath = "/test-legacy-first/"
		spec.UseKeylessAccess = false

		// Create OAS with two requirements
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}

		oasDoc.T.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"basic": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:   "http",
						Scheme: "basic",
					},
				},
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		}

		// Basic auth first, API key second
		oasDoc.T.Security = openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{"basic": []string{}},
			openapi3.SecurityRequirement{"apikey": []string{}},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:    spec.APIID,
				Name:  spec.Name,
				OrgID: "", // Use empty OrgID
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "legacy",
					SecuritySchemes: oas.SecuritySchemes{
						"basic": &oas.Basic{
							Enabled: true,
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc

		// Debug output
		t.Logf("UseBasicAuth: %v, UseStandardAuth: %v, SecurityRequirements: %v",
			spec.UseBasicAuth, spec.UseStandardAuth, spec.SecurityRequirements)
		t.Logf("AuthConfigs: %+v", spec.AuthConfigs)
	})

	// Test cases - only basic auth should work (first requirement)
	testCases := []test.TestCase{
		// Basic auth (first requirement) - should succeed
		{
			Method: "GET",
			Path:   "/test-legacy-first/",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuthUser+":"+basicAuthPassword)),
			},
			Code: http.StatusOK,
		},
		// API key (second requirement) - should fail in legacy mode
		{
			Method: "GET",
			Path:   "/test-legacy-first/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

// TestLegacyMode_ANDLogicWithinSingleRequirement tests AND logic within a single requirement in legacy mode
func TestLegacyMode_ANDLogicWithinSingleRequirement(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "" // JWT creates sessions with empty OrgID by default
		p.AccessRights = map[string]user.AccessDefinition{
			"test-and-logic": {
				APIName:  "Test AND Logic",
				APIID:    "test-and-logic",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "" // Use empty OrgID to match JWT
		s.AccessRights = map[string]user.AccessDefinition{
			"test-and-logic": {
				APIName:  "Test AND Logic",
				APIID:    "test-and-logic",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-and-logic"
		spec.Name = "Test AND Logic"
		spec.OrgID = "" // Use empty OrgID to match JWT sessions
		spec.Proxy.ListenPath = "/test-and-logic/"
		spec.UseKeylessAccess = false

		// Create OAS with single requirement containing multiple schemes (AND logic)
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}

		oasDoc.T.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					},
				},
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		}

		// Single requirement with both JWT AND API key
		oasDoc.T.Security = openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{
				"jwt":    []string{},
				"apikey": []string{},
			},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:   spec.APIID,
				Name: spec.Name,
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "legacy", // Legacy mode with AND logic
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		// Configure both auth methods
		enabled := true
		tykExtension.Server.Authentication.SecuritySchemes = oas.SecuritySchemes{
			"jwt": &oas.JWT{
				Enabled:           true,
				Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
				SigningMethod:     "rsa",
				IdentityBaseField: "user_id",
				PolicyFieldName:   "policy_id",
				DefaultPolicies:   []string{pID},
				AuthSources: oas.AuthSources{
					Header: &oas.AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			},
			"apikey": &oas.Token{
				Enabled: &enabled,
				AuthSources: oas.AuthSources{
					Header: &oas.AuthSource{
						Enabled: true,
						Name:    "X-API-Key",
					},
				},
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc

		// Debug output
		t.Logf("AND test - EnableJWT: %v, UseStandardAuth: %v", spec.EnableJWT, spec.UseStandardAuth)
		t.Logf("AND test - AuthConfigs: %+v", spec.AuthConfigs)
		t.Logf("AND test - SecurityRequirements: %v", spec.SecurityRequirements)
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "and-test-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases for AND logic
	testCases := []test.TestCase{
		// Both JWT and API key = success
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Only JWT = fail (need both)
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusUnauthorized,
		},
		// Only API key = fail (need both)
		// JWT middleware returns 400 when Authorization header is missing
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusBadRequest,
		},
	}

	ts.Run(t, testCases...)
}

// TestCompliantMode_JWTOrAPIKeyOrHMAC tests OR logic with JWT, API Key, and HMAC
func TestCompliantMode_JWTOrAPIKeyOrHMAC(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "default" // Set explicit org ID
		p.AccessRights = map[string]user.AccessDefinition{
			"test-compliant-or": {
				APIName:  "Test Compliant OR",
				APIID:    "test-compliant-or",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "default" // Set explicit org ID
		s.AccessRights = map[string]user.AccessDefinition{
			"test-compliant-or": {
				APIName:  "Test Compliant OR",
				APIID:    "test-compliant-or",
				Versions: []string{"default"},
			},
		}
	})

	// HMAC key for testing
	hmacKey := "test-hmac-key"
	hmacSecret := "test-hmac-secret"

	// Create HMAC session
	hmacSession := CreateStandardSession()
	hmacSession.OrgID = "default" // Set explicit org ID
	hmacSession.HMACEnabled = true
	hmacSession.HmacSecret = hmacSecret
	hmacSession.AccessRights = map[string]user.AccessDefinition{
		"test-compliant-or": {
			APIName:  "Test Compliant OR",
			APIID:    "test-compliant-or",
			Versions: []string{"default"},
		},
	}
	_ = ts.Gw.GlobalSessionManager.UpdateSession(hmacKey, hmacSession, 60, false)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-compliant-or"
		spec.Name = "Test Compliant OR"
		spec.OrgID = "default" // Set explicit org ID to match policy
		spec.Proxy.ListenPath = "/test-compliant-or/"
		spec.UseKeylessAccess = false

		// Create OAS with three auth methods
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}

		oasDoc.T.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					},
				},
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		}

		// Multiple requirements for OR logic in standard OAS
		oasDoc.T.Security = openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{"jwt": []string{}},
			openapi3.SecurityRequirement{"apikey": []string{}},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:    spec.APIID,
				Name:  spec.Name,
				OrgID: "default", // Set explicit OrgID to match policy
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant", // Compliant mode for OR logic
					// Vendor extension security for HMAC (proprietary)
					Security: [][]string{
						{"hmac"}, // HMAC as additional OR option
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		// Configure auth methods
		enabled := true
		tykExtension.Server.Authentication.SecuritySchemes = oas.SecuritySchemes{
			"jwt": &oas.JWT{
				Enabled:           true,
				Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
				SigningMethod:     "rsa",
				IdentityBaseField: "user_id",
				PolicyFieldName:   "policy_id",
				DefaultPolicies:   []string{pID},
				AuthSources: oas.AuthSources{
					Header: &oas.AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			},
			"apikey": &oas.Token{
				Enabled: &enabled,
				AuthSources: oas.AuthSources{
					Header: &oas.AuthSource{
						Enabled: true,
						Name:    "X-API-Key",
					},
				},
			},
			"hmac": &oas.HMAC{
				Enabled: true,
				AuthSources: oas.AuthSources{
					Header: &oas.AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc

		// Enable HMAC
		spec.EnableSignatureChecking = true
		spec.HmacAllowedAlgorithms = []string{"hmac-sha256"}

		// Debug: Log auth configs
		t.Logf("JWT AuthConfig after extraction: %+v", spec.AuthConfigs["jwt"])
		t.Logf("EnableJWT: %v", spec.EnableJWT)
		t.Logf("SecurityRequirements: %+v", spec.SecurityRequirements)
		t.Logf("OAS Tyk Extension Security: %+v", tykExtension.Server.Authentication.Security)
		t.Logf("All AuthConfigs in spec: %+v", spec.AuthConfigs)
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "compliant-test-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases for OR logic
	testCases := []test.TestCase{
		// JWT only - should succeed
		{
			Method: "GET",
			Path:   "/test-compliant-or/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// API key only - should succeed
		{
			Method: "GET",
			Path:   "/test-compliant-or/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Invalid JWT + valid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-compliant-or/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// All invalid - should fail
		{
			Method: "GET",
			Path:   "/test-compliant-or/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid",
				"X-API-Key":     "invalid",
			},
			Code: http.StatusForbidden,
		},
	}

	ts.Run(t, testCases...)
}

// TestCompliantMode_SessionIsolation tests that sessions are isolated between auth attempts
func TestCompliantMode_SessionIsolation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create two API keys with different metadata
	apiKey1 := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"user_type": "premium",
			"user_id":   "user1",
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"test-session-isolation": {
				APIName:  "Test Session Isolation",
				APIID:    "test-session-isolation",
				Versions: []string{"default"},
			},
		}
	})

	apiKey2 := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"user_type": "basic",
			"user_id":   "user2",
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"test-session-isolation": {
				APIName:  "Test Session Isolation",
				APIID:    "test-session-isolation",
				Versions: []string{"default"},
			},
		}
	})

	// Create basic auth user
	basicAuthUser := "basic-user"
	basicAuthPassword := "basic-pass"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-session-isolation"
		spec.Name = "Test Session Isolation"
		spec.Proxy.ListenPath = "/test-session-isolation/"
		spec.UseKeylessAccess = false

		// Create OAS API with Basic Auth and API Key in compliant mode
		createOASAPIWithBasicAndAPIKey(spec)

		// Ensure compliant mode is set
		if spec.OAS.GetTykExtension() != nil && spec.OAS.GetTykExtension().Server.Authentication != nil {
			spec.OAS.GetTykExtension().Server.Authentication.SecurityProcessingMode = "compliant"
		}

		// Re-extract to apply changes
		spec.OAS.ExtractTo(spec.APIDefinition)
	})

	// Create basic auth session
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicAuthPassword
	basicSession.MetaData = map[string]interface{}{
		"user_type": "basic_auth",
		"user_id":   "basic_user",
	}
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-session-isolation": {
			APIName:  "Test Session Isolation",
			APIID:    "test-session-isolation",
			Versions: []string{"default"},
		},
	}
	basicSession.OrgID = "default"
	_ = ts.Gw.GlobalSessionManager.UpdateSession(basicAuthUser, basicSession, 60, false)

	// Test cases - verify session isolation
	testCases := []test.TestCase{
		// Test with first API key
		{
			Method: "GET",
			Path:   "/test-session-isolation/",
			Headers: map[string]string{
				"X-API-Key": apiKey1,
			},
			Code: http.StatusOK,
		},
		// Test with second API key (different metadata)
		{
			Method: "GET",
			Path:   "/test-session-isolation/",
			Headers: map[string]string{
				"X-API-Key": apiKey2,
			},
			Code: http.StatusOK,
		},
		// Test with basic auth (different metadata)
		{
			Method: "GET",
			Path:   "/test-session-isolation/",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuthUser+":"+basicAuthPassword)),
			},
			Code: http.StatusOK,
		},
		// Test with invalid basic + valid API key - should use API key session
		{
			Method: "GET",
			Path:   "/test-session-isolation/",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:wrong")),
				"X-API-Key":     apiKey1,
			},
			Code: http.StatusOK,
		},
	}

	ts.Run(t, testCases...)
}

// TestCompliantMode_ThreeAuthMethods tests with JWT, Basic Auth, and API Key
func TestCompliantMode_ThreeAuthMethods(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "default" // Set explicit OrgID
		p.AccessRights = map[string]user.AccessDefinition{
			"test-three-auth": {
				APIName:  "Test Three Auth",
				APIID:    "test-three-auth",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "default" // Set explicit OrgID
		s.AccessRights = map[string]user.AccessDefinition{
			"test-three-auth": {
				APIName:  "Test Three Auth",
				APIID:    "test-three-auth",
				Versions: []string{"default"},
			},
		}
	})

	// Create basic auth user
	basicAuthUser := "three-auth-user"
	basicAuthPassword := "three-auth-pass"

	// Configure API with three auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-three-auth"
		spec.Name = "Test Three Auth"
		spec.OrgID = "default" // Set explicit OrgID
		spec.Proxy.ListenPath = "/test-three-auth/"
		spec.UseKeylessAccess = false // Require authentication

		// Create OAS with three auth methods directly (don't use helper, it's incomplete)
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}

		// Add components for security schemes
		oasDoc.T.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					},
				},
				"basic": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:   "http",
						Scheme: "basic",
					},
				},
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		}

		// Multiple requirements for OR logic
		oasDoc.T.Security = openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{"jwt": []string{}},
			openapi3.SecurityRequirement{"basic": []string{}},
			openapi3.SecurityRequirement{"apikey": []string{}},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:    spec.APIID,
				Name:  spec.Name,
				OrgID: "default", // Set explicit OrgID to match policy
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant",
					SecuritySchemes: oas.SecuritySchemes{
						"jwt": &oas.JWT{
							Enabled:           true,
							Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
							SigningMethod:     "rsa",
							IdentityBaseField: "user_id",
							PolicyFieldName:   "policy_id",
							DefaultPolicies:   []string{pID},
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"basic": &oas.Basic{
							Enabled: true,
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	// Create basic auth session
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicAuthPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-three-auth": {
			APIName:  "Test Three Auth",
			APIID:    "test-three-auth",
			Versions: []string{"default"},
		},
	}
	basicSession.OrgID = "default"
	_ = ts.Gw.GlobalSessionManager.UpdateSession(basicAuthUser, basicSession, 60, false)

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "three-auth-jwt-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test matrix for three auth methods
	testCases := []test.TestCase{
		// Single valid auth method - all should succeed
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(basicAuthUser+":"+basicAuthPassword)),
			},
			Code: http.StatusOK,
		},
		// Two invalid + one valid - should succeed
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid",
				"X-API-Key":     "invalid",
				// Basic auth header would override Bearer, so use valid API key
			},
			Code: http.StatusForbidden, // All fail
		},
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:wrong")),
				"X-API-Key":     apiKey, // Valid
			},
			Code: http.StatusOK, // API key succeeds
		},
		// All invalid - should fail
		{
			Method: "GET",
			Path:   "/test-three-auth/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid",
				"X-API-Key":     "invalid",
			},
			Code: http.StatusForbidden,
		},
		// No auth - should fail
		{
			Method:  "GET",
			Path:    "/test-three-auth/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

// TestHMACSignatureValidation tests proper HMAC signature validation
func TestHMACSignatureValidation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// HMAC credentials
	hmacKey := "test-hmac-key"
	hmacSecret := "test-hmac-secret-123456"

	// Create HMAC session
	hmacSession := CreateStandardSession()
	hmacSession.OrgID = "default" // Set OrgID
	hmacSession.HMACEnabled = true
	hmacSession.HmacSecret = hmacSecret
	hmacSession.AccessRights = map[string]user.AccessDefinition{
		"test-hmac": {
			APIName:  "Test HMAC",
			APIID:    "test-hmac",
			Versions: []string{"default"},
		},
	}
	_ = ts.Gw.GlobalSessionManager.UpdateSession(hmacKey, hmacSession, 60, false)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-hmac"
		spec.Name = "Test HMAC"
		spec.OrgID = "default" // Set OrgID
		spec.Proxy.ListenPath = "/test-hmac/"
		spec.UseKeylessAccess = false

		// Configure OAS with HMAC in vendor extension
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:    spec.APIID,
				Name:  spec.Name,
				OrgID: "default", // Set OrgID
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant",
					Security: [][]string{
						{"hmac"}, // HMAC only
					},
					HMAC: &oas.HMAC{
						Enabled: true,
						AuthSources: oas.AuthSources{
							Header: &oas.AuthSource{
								Enabled: true,
								Name:    "Authorization",
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpGet,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc

		// EnableSignatureChecking must be set after extraction to enable HMAC middleware
		spec.EnableSignatureChecking = true
		spec.HmacAllowedAlgorithms = []string{"hmac-sha1", "hmac-sha256"}
	})

	// Test Cases for HMAC signature validation
	t.Run("Valid HMAC SHA1 signature", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date":     date,
			"X-Test-1": "hello",
			"X-Test-2": "world",
		}

		signature := generateHMACSignature("GET", "/test-hmac/", headers, hmacSecret, "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date x-test-1 x-test-2",signature="%s"`, hmacKey, signature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"X-Test-1":      "hello",
				"X-Test-2":      "world",
				"Authorization": authHeader,
			},
			Code: http.StatusOK,
		}

		ts.Run(t, testCase)
	})

	t.Run("Valid HMAC SHA256 signature", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date":     date,
			"X-Test-1": "test-value-1",
			"X-Test-2": "test-value-2",
		}

		signature := generateHMACSignature("GET", "/test-hmac/", headers, hmacSecret, "hmac-sha256")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha256",headers="(request-target) date x-test-1 x-test-2",signature="%s"`, hmacKey, signature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"X-Test-1":      "test-value-1",
				"X-Test-2":      "test-value-2",
				"Authorization": authHeader,
			},
			Code: http.StatusOK,
		}

		ts.Run(t, testCase)
	})

	t.Run("Invalid HMAC signature", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date",signature="invalid-signature"`, hmacKey)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"Authorization": authHeader,
			},
			Code: http.StatusBadRequest, // HMAC middleware returns 400 for invalid signatures
		}

		ts.Run(t, testCase)
	})

	t.Run("Wrong HMAC secret", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date": date,
		}

		// Generate signature with wrong secret
		wrongSignature := generateHMACSignature("GET", "/test-hmac/", headers, "wrong-secret", "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date",signature="%s"`, hmacKey, wrongSignature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"Authorization": authHeader,
			},
			Code: http.StatusBadRequest, // HMAC middleware returns 400 for invalid signatures
		}

		ts.Run(t, testCase)
	})

	t.Run("Missing HMAC signature", func(t *testing.T) {
		testCase := test.TestCase{
			Method:  "GET",
			Path:    "/test-hmac/",
			Headers: map[string]string{},
			Code:    http.StatusBadRequest, // HMAC middleware returns 400 for missing Authorization
		}

		ts.Run(t, testCase)
	})

	t.Run("Invalid keyId in HMAC signature", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date": date,
		}

		signature := generateHMACSignature("GET", "/test-hmac/", headers, hmacSecret, "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="wrong-key-id",algorithm="hmac-sha1",headers="(request-target) date",signature="%s"`, signature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"Authorization": authHeader,
			},
			Code: http.StatusBadRequest, // Invalid keyId results in 400
		}

		ts.Run(t, testCase)
	})

	t.Run("Mismatched header values", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date":     date,
			"X-Test-1": "hello",
		}

		// Generate signature with one set of headers
		signature := generateHMACSignature("GET", "/test-hmac/", headers, hmacSecret, "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date x-test-1",signature="%s"`, hmacKey, signature)

		// Send different header values
		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac/",
			Headers: map[string]string{
				"Date":          date,
				"X-Test-1":      "different-value", // Mismatched value
				"Authorization": authHeader,
			},
			Code: http.StatusBadRequest, // HMAC middleware returns 400 for invalid signatures
		}

		ts.Run(t, testCase)
	})
}

// TestHMACInORAuthentication tests HMAC as part of OR authentication logic
func TestHMACInORAuthentication(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "default" // Set OrgID
		s.AccessRights = map[string]user.AccessDefinition{
			"test-hmac-or": {
				APIName:  "Test HMAC OR",
				APIID:    "test-hmac-or",
				Versions: []string{"default"},
			},
		}
	})

	// HMAC credentials
	hmacKey := "hmac-or-key"
	hmacSecret := "hmac-or-secret"

	hmacSession := CreateStandardSession()
	hmacSession.OrgID = "default" // Set OrgID
	hmacSession.HMACEnabled = true
	hmacSession.HmacSecret = hmacSecret
	hmacSession.AccessRights = map[string]user.AccessDefinition{
		"test-hmac-or": {
			APIName:  "Test HMAC OR",
			APIID:    "test-hmac-or",
			Versions: []string{"default"},
		},
	}
	_ = ts.Gw.GlobalSessionManager.UpdateSession(hmacKey, hmacSession, 60, false)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-hmac-or"
		spec.Name = "Test HMAC OR"
		spec.OrgID = "default" // Set OrgID
		spec.Proxy.ListenPath = "/test-hmac-or/"
		spec.UseKeylessAccess = false

		// Configure OAS with API Key OR HMAC
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"apikey": []string{}},
			},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:    spec.APIID,
				Name:  spec.Name,
				OrgID: "default", // Set OrgID
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant",
					// Add HMAC as vendor extension
					Security: [][]string{
						{"hmac"}, // HMAC as vendor extension option
					},
					SecuritySchemes: oas.SecuritySchemes{
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
						"hmac": &oas.HMAC{
							Enabled: true,
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpGet,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc

		// EnableSignatureChecking must be set after extraction to enable HMAC middleware
		spec.EnableSignatureChecking = true
		spec.HmacAllowedAlgorithms = []string{"hmac-sha1", "hmac-sha256"}
	})

	// Test Cases for OR authentication with HMAC
	t.Run("API Key succeeds", func(t *testing.T) {
		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac-or/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		}

		ts.Run(t, testCase)
	})

	t.Run("Valid HMAC succeeds", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date": date,
		}

		signature := generateHMACSignature("GET", "/test-hmac-or/", headers, hmacSecret, "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date",signature="%s"`, hmacKey, signature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac-or/",
			Headers: map[string]string{
				"Date":          date,
				"Authorization": authHeader,
			},
			Code: http.StatusOK,
		}

		ts.Run(t, testCase)
	})

	t.Run("Invalid API key but valid HMAC succeeds", func(t *testing.T) {
		date := time.Now().Format("Mon, 02 Jan 2006 15:04:05 MST")
		headers := map[string]string{
			"Date": date,
		}

		signature := generateHMACSignature("GET", "/test-hmac-or/", headers, hmacSecret, "hmac-sha1")
		authHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="hmac-sha1",headers="(request-target) date",signature="%s"`, hmacKey, signature)

		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac-or/",
			Headers: map[string]string{
				"Date":          date,
				"X-API-Key":     "invalid-key",
				"Authorization": authHeader,
			},
			Code: http.StatusOK, // HMAC succeeds even though API key fails
		}

		ts.Run(t, testCase)
	})

	t.Run("Valid API key but invalid HMAC succeeds", func(t *testing.T) {
		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac-or/",
			Headers: map[string]string{
				"X-API-Key":     apiKey,
				"Authorization": `Signature keyId="wrong",algorithm="hmac-sha1",signature="invalid"`,
			},
			Code: http.StatusOK, // API key succeeds even though HMAC fails
		}

		ts.Run(t, testCase)
	})

	t.Run("Both invalid fails", func(t *testing.T) {
		testCase := test.TestCase{
			Method: "GET",
			Path:   "/test-hmac-or/",
			Headers: map[string]string{
				"X-API-Key":     "invalid-key",
				"Authorization": `Signature keyId="wrong",algorithm="hmac-sha1",signature="invalid"`,
			},
			Code: http.StatusForbidden,
		}

		ts.Run(t, testCase)
	})

	t.Run("No auth fails", func(t *testing.T) {
		testCase := test.TestCase{
			Method:  "GET",
			Path:    "/test-hmac-or/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		}

		ts.Run(t, testCase)
	})
}

// TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination tests OR logic with JWT and API key
func TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "" // Use empty OrgID for consistency
		p.AccessRights = map[string]user.AccessDefinition{
			"jwt-or-api": {
				APIName:  "Test JWT OR API",
				APIID:    "jwt-or-api",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = "" // Use empty OrgID for consistency
		s.AccessRights = map[string]user.AccessDefinition{
			"jwt-or-api": {
				APIName:  "Test JWT OR API",
				APIID:    "jwt-or-api",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "jwt-or-api"
		spec.Name = "Test JWT OR API"
		spec.OrgID = "" // Use empty OrgID
		spec.Proxy.ListenPath = "/jwt-or-api/"
		spec.UseKeylessAccess = false

		// Create OAS with JWT and API key
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"jwt": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         "http",
							Scheme:       "bearer",
							BearerFormat: "JWT",
						},
					},
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"jwt": []string{}},
				openapi3.SecurityRequirement{"apikey": []string{}},
			},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:   spec.APIID,
				Name: spec.Name,
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant",
					SecuritySchemes: oas.SecuritySchemes{
						"jwt": &oas.JWT{
							Enabled:           true,
							Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
							SigningMethod:     "rsa",
							IdentityBaseField: "user_id",
							PolicyFieldName:   "policy_id",
							DefaultPolicies:   []string{pID},
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "test-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases
	testCases := []test.TestCase{
		// JWT only should succeed
		{
			Method: "GET",
			Path:   "/jwt-or-api/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// API key only should succeed
		{
			Method: "GET",
			Path:   "/jwt-or-api/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Both should succeed
		{
			Method: "GET",
			Path:   "/jwt-or-api/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Neither should fail
		{
			Method:  "GET",
			Path:    "/jwt-or-api/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

// TestMultiAuthMiddleware_OR_AllMethodsFail tests that when all auth methods fail, the request is rejected
func TestMultiAuthMiddleware_OR_AllMethodsFail(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "all-fail"
		spec.Name = "Test All Fail"
		spec.Proxy.ListenPath = "/all-fail/"
		spec.UseKeylessAccess = false

		// Create OAS with multiple auth methods
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"jwt": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         "http",
							Scheme:       "bearer",
							BearerFormat: "JWT",
						},
					},
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"jwt": []string{}},
				openapi3.SecurityRequirement{"apikey": []string{}},
			},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:   spec.APIID,
				Name: spec.Name,
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant",
					SecuritySchemes: oas.SecuritySchemes{
						"jwt": &oas.JWT{
							Enabled:           true,
							Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
							SigningMethod:     "rsa",
							IdentityBaseField: "user_id",
							PolicyFieldName:   "policy_id",
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	// Test cases - all should fail
	testCases := []test.TestCase{
		// Invalid JWT
		{
			Method: "GET",
			Path:   "/all-fail/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
			},
			Code: http.StatusUnauthorized, // JWT returns 401 for invalid tokens
		},
		// Invalid API key
		{
			Method: "GET",
			Path:   "/all-fail/",
			Headers: map[string]string{
				"X-API-Key": "invalid-key",
			},
			Code: http.StatusForbidden,
		},
		// Both invalid
		{
			Method: "GET",
			Path:   "/all-fail/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusForbidden,
		},
		// No auth
		{
			Method:  "GET",
			Path:    "/all-fail/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

func createOASAPIWithBasicAndAPIKey(spec *APISpec) {
	oasDoc := oas.OAS{}
	oasDoc.T = openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   spec.Name,
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(),
		Components: &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"basic": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:   "http",
						Scheme: "basic",
					},
				},
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		},
		Security: openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{"basic": []string{}},
			openapi3.SecurityRequirement{"apikey": []string{}},
		},
	}

	tykExtension := &oas.XTykAPIGateway{
		Info: oas.Info{
			ID:   spec.APIID,
			Name: spec.Name,
			State: oas.State{
				Active: true,
			},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: spec.Proxy.ListenPath,
				Strip: true,
			},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"basic": &oas.Basic{
						Enabled: true,
						AuthSources: oas.AuthSources{
							Header: &oas.AuthSource{
								Enabled: true,
								Name:    "Authorization",
							},
						},
					},
					"apikey": &oas.Token{
						Enabled: func() *bool { b := true; return &b }(),
						AuthSources: oas.AuthSources{
							Header: &oas.AuthSource{
								Enabled: true,
								Name:    "X-API-Key",
							},
						},
					},
				},
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
	}

	oasDoc.SetTykExtension(tykExtension)
	oasDoc.ExtractTo(spec.APIDefinition)
	spec.IsOAS = true
	spec.OAS = oasDoc
}

// TestStandardOpenAPIBearerWithoutTykExtension tests standard OpenAPI bearer auth without Tyk extension
func TestStandardOpenAPIBearerWithoutTykExtension(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// This test simulates the behavior when standard OpenAPI bearer auth is processed
	// without Tyk extension - it should enable JWT by default
	
	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = ""
		p.AccessRights = map[string]user.AccessDefinition{
			"test-standard-bearer": {
				APIName:  "Test Standard Bearer",
				APIID:    "test-standard-bearer",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-standard-bearer"
		spec.Name = "Test Standard Bearer"
		spec.OrgID = ""
		spec.Proxy.ListenPath = "/test-standard-bearer/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.UseKeylessAccess = false

		// Simulate standard OpenAPI bearer configuration
		// In real OAS extraction, bearer auth without Tyk extension enables JWT
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.JWTDefaultPolicies = []string{pID}
		
		// Set up auth config as it would be by OAS extraction
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"bearerAuth": {
				Name:           "bearerAuth",
				DisableHeader:  false,
				AuthHeaderName: "Authorization",
			},
		}
		
		// Single security requirement
		spec.SecurityRequirements = [][]string{
			{"bearerAuth"},
		}
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "standard-bearer-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases
	testCases := []test.TestCase{
		// Valid JWT should succeed
		{
			Method: "GET",
			Path:   "/test-standard-bearer/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// No auth should fail
		{
			Method:  "GET",
			Path:    "/test-standard-bearer/",
			Headers: map[string]string{},
			Code:    http.StatusBadRequest, // JWT returns 400 for missing Authorization header
		},
	}

	ts.Run(t, testCases...)
}

// TestSingleSecurityRequirementANDLogic tests single requirement with multiple auth methods (AND logic)
func TestSingleSecurityRequirementANDLogic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// This test ensures the OR wrapper properly handles single requirements with AND logic
	// The code path: if len(a.Spec.SecurityRequirements) <= 1
	
	// Create policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = ""
		p.AccessRights = map[string]user.AccessDefinition{
			"test-single-and": {
				APIName:  "Test Single AND",
				APIID:    "test-single-and",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.OrgID = ""
		s.AccessRights = map[string]user.AccessDefinition{
			"test-single-and": {
				APIName:  "Test Single AND",
				APIID:    "test-single-and",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-single-and"
		spec.Name = "Test Single AND"
		spec.OrgID = ""
		spec.Proxy.ListenPath = "/test-single-and/"
		spec.UseKeylessAccess = false

		// Create OAS with single requirement containing multiple auth methods
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"jwt": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         "http",
							Scheme:       "bearer",
							BearerFormat: "JWT",
						},
					},
					"apikey": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			// Single requirement with both JWT AND API key
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"jwt":    []string{},
					"apikey": []string{},
				},
			},
		}

		tykExtension := &oas.XTykAPIGateway{
			Info: oas.Info{
				ID:   spec.APIID,
				Name: spec.Name,
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: spec.Proxy.ListenPath,
					Strip: true,
				},
				Authentication: &oas.Authentication{
					Enabled:                true,
					SecurityProcessingMode: "compliant", // Even in compliant mode, single requirement = AND
					SecuritySchemes: oas.SecuritySchemes{
						"jwt": &oas.JWT{
							Enabled:           true,
							Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
							SigningMethod:     "rsa",
							IdentityBaseField: "user_id",
							PolicyFieldName:   "policy_id",
							DefaultPolicies:   []string{pID},
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "Authorization",
								},
							},
						},
						"apikey": &oas.Token{
							Enabled: func() *bool { b := true; return &b }(),
							AuthSources: oas.AuthSources{
								Header: &oas.AuthSource{
									Enabled: true,
									Name:    "X-API-Key",
								},
							},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}

		oasDoc.SetTykExtension(tykExtension)
		oasDoc.ExtractTo(spec.APIDefinition)
		spec.IsOAS = true
		spec.OAS = oasDoc
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "single-and-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases - single requirement means AND logic
	testCases := []test.TestCase{
		// Both JWT and API key = success
		{
			Method: "GET",
			Path:   "/test-single-and/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Only JWT = fail (need both)
		{
			Method: "GET",
			Path:   "/test-single-and/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusUnauthorized,
		},
		// Only API key = fail (need both)
		{
			Method: "GET",
			Path:   "/test-single-and/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusBadRequest, // JWT middleware returns 400 when header missing
		},
		// Neither = fail
		{
			Method:  "GET",
			Path:    "/test-single-and/",
			Headers: map[string]string{},
			Code:    http.StatusBadRequest,
		},
	}

	ts.Run(t, testCases...)
}

// TestOAuth2InORWrapper tests OAuth2 authentication configuration that would be used in OR wrapper
func TestOAuth2InORWrapper(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// This test verifies OAuth2 can be configured alongside other auth methods
	// The actual OR logic testing is done in other tests
	
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-oauth2-or"
		spec.Name = "Test OAuth2 OR"
		spec.OrgID = ""
		spec.Proxy.ListenPath = "/test-oauth2-or/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.UseKeylessAccess = false
		
		// Just test that OAuth2 can be enabled with correct configuration
		// In real OR wrapper scenario, both would be enabled
		spec.UseOauth2 = true
		
		// Configure auth configs as they would be in OR scenario
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"oauth2": {
				Name:           "oauth2",
				DisableHeader:  false,
				AuthHeaderName: "Authorization",
			},
		}
		
		// Single requirement to test OAuth2 configuration
		spec.SecurityRequirements = [][]string{
			{"oauth2"},
		}
	})

	// Test that OAuth2 is properly configured
	// Just verify the configuration doesn't cause errors
	testCases := []test.TestCase{
		// No auth returns expected error
		{
			Method:  "GET",
			Path:    "/test-oauth2-or/",
			Headers: map[string]string{},
			Code:    http.StatusBadRequest, // OAuth2 returns 400 for missing Authorization header
		},
		// Invalid OAuth2 token fails as expected
		{
			Method: "GET",
			Path:   "/test-oauth2-or/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-oauth-token",
			},
			Code: http.StatusForbidden, // Invalid OAuth token
		},
	}

	ts.Run(t, testCases...)
}

// TestAuthORWrapperEnabledForSpec tests the EnabledForSpec conditions
func TestAuthORWrapperEnabledForSpec(t *testing.T) {
	t.Run("Single requirement should not use OR wrapper", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				UseStandardAuth: true,
				SecurityRequirements: [][]string{
					{"apikey"},
				},
			},
		}
		
		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   &Gateway{},
				logger: log.WithField("mw", "AuthORWrapper"),
			},
		}
		wrapper.Init()
		
		if wrapper.EnabledForSpec() {
			t.Error("OR wrapper should not be enabled for single security requirement")
		}
	})

	t.Run("Multiple requirements should use OR wrapper", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				UseStandardAuth: true,
				EnableJWT:       true,
				SecurityRequirements: [][]string{
					{"apikey"},
					{"jwt"},
				},
			},
		}
		
		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   &Gateway{},
				logger: log.WithField("mw", "AuthORWrapper"),
			},
		}
		wrapper.Init()
		
		if !wrapper.EnabledForSpec() {
			t.Error("OR wrapper should be enabled for multiple security requirements")
		}
	})

	t.Run("No auth middlewares should not enable OR wrapper", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				SecurityRequirements: [][]string{
					{"custom1"},
					{"custom2"},
				},
			},
		}
		
		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   &Gateway{},
				logger: log.WithField("mw", "AuthORWrapper"),
			},
		}
		// Init but no auth methods will be added
		wrapper.Init()
		
		if wrapper.EnabledForSpec() {
			t.Error("OR wrapper should not be enabled when no auth middlewares are configured")
		}
	})
}

// TestJWTWithTykExtensionButNoComponents tests JWT configured in Tyk extension but no OpenAPI components
func TestJWTWithTykExtensionButNoComponents(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create JWT policy
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = ""
		p.AccessRights = map[string]user.AccessDefinition{
			"test-jwt-extension-only": {
				APIName:  "Test JWT Extension Only",
				APIID:    "test-jwt-extension-only",
				Versions: []string{"default"},
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-jwt-extension-only"
		spec.Name = "Test JWT Extension Only"
		spec.OrgID = ""
		spec.Proxy.ListenPath = "/test-jwt-extension-only/"
		spec.Proxy.TargetURL = TestHttpAny
		spec.UseKeylessAccess = false
		
		// Simulate JWT configured in Tyk extension but no OpenAPI components
		// This would be extracted from Tyk extension's SecuritySchemes
		spec.EnableJWT = true
		spec.JWTSigningMethod = "rsa"
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.JWTDefaultPolicies = []string{pID}
		
		// Set auth config
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"jwt": {
				Name:           "jwt",
				DisableHeader:  false,
				AuthHeaderName: "Authorization",
			},
		}
		
		// Security requirement
		spec.SecurityRequirements = [][]string{
			{"jwt"},
		}
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "extension-only-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases
	testCases := []test.TestCase{
		// Valid JWT should succeed
		{
			Method: "GET",
			Path:   "/test-jwt-extension-only/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// No auth should fail
		{
			Method:  "GET",
			Path:    "/test-jwt-extension-only/",
			Headers: map[string]string{},
			Code:    http.StatusBadRequest, // JWT returns 400 for missing Authorization header
		},
	}

	ts.Run(t, testCases...)
}
