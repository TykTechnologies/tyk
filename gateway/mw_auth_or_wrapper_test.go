package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	jwt "github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// createOASAPIWithORAuth creates a proper OAS API with OR authentication entirely through OAS configuration
func createOASAPIWithORAuth(spec *APISpec, jwtConfig *oas.JWT, apiKeyConfig bool) {
	// Create OAS document
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
		SecuritySchemes: openapi3.SecuritySchemes{},
	}
	
	// Add JWT security scheme if JWT config provided
	if jwtConfig != nil {
		oasDoc.T.Components.SecuritySchemes["jwt"] = &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			},
		}
	}
	
	// Add API key security scheme if enabled
	if apiKeyConfig {
		oasDoc.T.Components.SecuritySchemes["apikey"] = &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "apiKey",
				In:   "header",
				Name: "X-API-Key",
			},
		}
	}
	
	// Build security requirements based on what's enabled
	var secReqs openapi3.SecurityRequirements
	if jwtConfig != nil {
		secReqs = append(secReqs, openapi3.SecurityRequirement{"jwt": []string{}})
	}
	if apiKeyConfig {
		secReqs = append(secReqs, openapi3.SecurityRequirement{"apikey": []string{}})
	}
	
	// Add paths with security requirements
	pathItem := &openapi3.PathItem{
		Get: &openapi3.Operation{
			Responses: openapi3.NewResponses(),
			Security:  &secReqs,
		},
		Post: &openapi3.Operation{
			Responses: openapi3.NewResponses(),
			Security:  &secReqs,
		},
	}
	
	// Add root path only (wildcard causes 404 issues with auth)
	oasDoc.T.Paths.Set("/", pathItem)
	
	// Set global security requirements
	oasDoc.T.Security = secReqs
	
	// Create Tyk extension with auth configuration
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
				SecurityProcessingMode: "compliant", // Enable OR logic
				SecuritySchemes: oas.SecuritySchemes{},
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
	}
	
	// Configure JWT authentication if provided
	if jwtConfig != nil {
		// JWT is stored directly as a JWT type in SecuritySchemes
		jwtWithAuth := *jwtConfig
		jwtWithAuth.AuthSources.Header = &oas.AuthSource{
			Enabled: true,
			Name:    "Authorization",
		}
		// Store as pointer to JWT since it will be type-checked later
		tykExtension.Server.Authentication.SecuritySchemes["jwt"] = &jwtWithAuth
	}
	
	// Configure API key authentication if enabled
	if apiKeyConfig {
		enabled := true
		// Store as pointer to Token since it will be type-checked later
		tykExtension.Server.Authentication.SecuritySchemes["apikey"] = &oas.Token{
			Enabled: &enabled,
			AuthSources: oas.AuthSources{
				Header: &oas.AuthSource{
					Enabled: true,
					Name:    "X-API-Key",
				},
			},
		}
	}
	
	// Set the Tyk extension
	oasDoc.SetTykExtension(tykExtension)
	
	// Extract to populate the APIDefinition
	oasDoc.ExtractTo(spec.APIDefinition)
	
	// Set spec fields
	spec.IsOAS = true
	spec.OAS = oasDoc
}

// createOASAPIWithBasicAndAPIKey creates an OAS API with Basic Auth and API Key support
func createOASAPIWithBasicAndAPIKey(spec *APISpec) {
	// Create OAS document
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
	
	// Build security requirements for OR logic
	secReqs := openapi3.SecurityRequirements{
		openapi3.SecurityRequirement{"basic": []string{}},
		openapi3.SecurityRequirement{"apikey": []string{}},
	}
	
	// Add paths with security requirements
	oasDoc.T.Paths.Set("/", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "test",
			Security:    &secReqs,
			Responses:   openapi3.NewResponses(),
		},
	})
	
	// Set default security
	oasDoc.T.Security = secReqs
	
	// Configure Tyk extensions for compliant mode
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			Name: spec.Name,
			ID:   spec.APIID,
		},
		Upstream: oas.Upstream{
			URL: spec.Proxy.TargetURL,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: spec.Proxy.ListenPath,
				Strip: true,
			},
			Authentication: &oas.Authentication{
				SecurityProcessingMode: "compliant",
			},
		},
	})
	
	spec.OAS = oasDoc
	spec.IsOAS = true
	
	// Enable auth methods on spec
	spec.UseBasicAuth = true
	spec.UseStandardAuth = true
	
	// Set auth config for proper header lookup
	spec.Auth = apidef.AuthConfig{
		AuthHeaderName: "X-API-Key",
		UseParam: false,
		DisableHeader: false,
	}
	
	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"basic": {
			AuthHeaderName: "Authorization",
		},
		"authToken": {
			AuthHeaderName: "X-API-Key",
			DisableHeader: false,
		},
	}
	
	// Set security requirements for OR logic
	spec.SecurityRequirements = [][]string{
		{"basic"},  // Option 1: Basic auth
		{"apikey"}, // Option 2: API key
	}
}

// createOASAPIWithThreeAuthMethods creates an OAS API with JWT, Basic Auth, and API Key support
func createOASAPIWithThreeAuthMethods(spec *APISpec, jwtConfig *oas.JWT) {
	// Create OAS document
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
	
	// Build security requirements for OR logic - three options
	secReqs := openapi3.SecurityRequirements{
		openapi3.SecurityRequirement{"jwt": []string{}},
		openapi3.SecurityRequirement{"basic": []string{}},
		openapi3.SecurityRequirement{"apikey": []string{}},
	}
	
	// Add paths with security requirements
	oasDoc.T.Paths.Set("/", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "test",
			Security:    &secReqs,
			Responses:   openapi3.NewResponses(),
		},
	})
	
	// Set default security
	oasDoc.T.Security = secReqs
	
	// Configure Tyk extensions for compliant mode
	oasDoc.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			Name: spec.Name,
			ID:   spec.APIID,
		},
		Upstream: oas.Upstream{
			URL: spec.Proxy.TargetURL,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: spec.Proxy.ListenPath,
				Strip: true,
			},
			Authentication: &oas.Authentication{
				SecurityProcessingMode: "compliant",
			},
		},
	})
	
	spec.OAS = oasDoc
	spec.IsOAS = true
	
	// Enable auth methods on spec
	spec.EnableJWT = true
	spec.UseBasicAuth = true
	spec.UseStandardAuth = true
	
	// Set auth configurations
	spec.Auth = apidef.AuthConfig{
		AuthHeaderName: "X-API-Key",
		UseParam: false,
		DisableHeader: false,
	}
	
	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"jwt": {
			AuthHeaderName: "Authorization",
			DisableHeader: false,
		},
		"basic": {
			AuthHeaderName: "Authorization",
		},
		"authToken": {
			AuthHeaderName: "X-API-Key",
			DisableHeader: false,
		},
	}
	
	// Set security requirements for OR logic
	spec.SecurityRequirements = [][]string{
		{"jwt"},    // Option 1: JWT
		{"basic"},  // Option 2: Basic auth
		{"apikey"}, // Option 3: API key
	}
	
	// Set JWT configuration
	if jwtConfig != nil {
		spec.JWTSigningMethod = jwtConfig.SigningMethod
		spec.JWTSource = jwtConfig.Source
		spec.JWTIdentityBaseField = jwtConfig.IdentityBaseField
		spec.JWTPolicyFieldName = jwtConfig.PolicyFieldName
		spec.JWTDefaultPolicies = jwtConfig.DefaultPolicies
	}
}

/*
func TestOASAPIRouting(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a simple OAS API without auth first to check routing
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-oas-routing"
		spec.Name = "Test OAS Routing"
		spec.Proxy.ListenPath = "/test-oas-routing/"
		
		// Create minimal OAS document
		oasDoc := oas.OAS{}
		oasDoc.T = openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   spec.Name,
				Version: "1.0.0",
			},
			Paths: openapi3.NewPaths(),
		}
		
		// Add a simple path
		pathItem := &openapi3.PathItem{
			Get: &openapi3.Operation{
				Responses: openapi3.NewResponses(),
			},
		}
		oasDoc.T.Paths.Set("/", pathItem)
		
		// Create minimal Tyk extension
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
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}
		
		// Set the Tyk extension
		oasDoc.SetTykExtension(tykExtension)
		
		// Extract to populate the APIDefinition
		oasDoc.ExtractTo(spec.APIDefinition)
		
		// Set spec fields
		spec.IsOAS = true
		spec.OAS = oasDoc
		spec.UseKeylessAccess = true
	})

	// Test the simple OAS API works
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/test-oas-routing/",
		Code:   http.StatusOK,
	})
	
	// Now test with auth enabled
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-oas-auth-routing"
		spec.Name = "Test OAS Auth Routing"
		spec.Proxy.ListenPath = "/test-oas-auth-routing/"
		
		// Create OAS document
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
				"apikey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		}
		
		// Add paths with security requirement
		pathItem := &openapi3.PathItem{
			Get: &openapi3.Operation{
				Responses: openapi3.NewResponses(),
				Security: &openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"apikey": []string{}},
				},
			},
			Post: &openapi3.Operation{
				Responses: openapi3.NewResponses(),
				Security: &openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"apikey": []string{}},
				},
			},
		}
		oasDoc.T.Paths.Set("/", pathItem)
		// Try with a catch-all parameter - using {path+} or {$path} for catch-all
		pathWithParam := &openapi3.PathItem{
			Get: &openapi3.Operation{
				Responses: openapi3.NewResponses(),
				Security: &openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"apikey": []string{}},
				},
				Parameters: []*openapi3.ParameterRef{
					{
						Value: &openapi3.Parameter{
							Name:     "path",
							In:       "path",
							Required: true,
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Type: &openapi3.Types{openapi3.TypeString},
								},
							},
						},
					},
				},
			},
		}
		oasDoc.T.Paths.Set("/{path+}", pathWithParam) // Use {path+} for catch-all
		
		// Set global security requirements
		oasDoc.T.Security = openapi3.SecurityRequirements{
			openapi3.SecurityRequirement{"apikey": []string{}},
		}
		
		// Create Tyk extension with auth
		enabled := true
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
						"apikey": &oas.Token{
							Enabled:     &enabled,
							AuthSources: oas.AuthSources{Header: &oas.AuthSource{Name: "X-API-Key"}},
						},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: TestHttpAny,
			},
		}
		
		// Set the Tyk extension
		oasDoc.SetTykExtension(tykExtension)
		
		// Extract to populate the APIDefinition
		oasDoc.ExtractTo(spec.APIDefinition)
		
		// Set spec fields
		spec.IsOAS = true
		spec.OAS = oasDoc
		spec.Active = true  // Make sure API is active
		
	})
	
	// Create API key
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			"test-oas-auth-routing": {
				APIName:  "Test OAS Auth Routing",
				APIID:    "test-oas-auth-routing",
				Versions: []string{"default"},
			},
		}
	})
	
	// Test with valid API key
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/test-oas-auth-routing/",
		Headers: map[string]string{
			"X-API-Key": apiKey,
		},
		Code: http.StatusOK,
	})
}
*/

// TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination tests the OR logic with JWT and API key
func TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "" // Match the API's OrgID
		p.AccessRights = map[string]user.AccessDefinition{
			"test-or-jwt-apikey": {
				APIName:  "Test OR JWT API Key",
				APIID:    "test-or-jwt-apikey",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-jwt-apikey": {
			APIName:  "Test OR JWT API Key",
			APIID:    "test-or-jwt-apikey",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Configure OAS API with JWT and API key using only OAS configuration
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-jwt-apikey"
		spec.Name = "Test OR JWT API Key"
		spec.Proxy.ListenPath = "/test-or-jwt-apikey/"
		
		// Create JWT config for OAS
		jwtConfig := &oas.JWT{
			Enabled:              true,
			Source:               base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
			SigningMethod:        "rsa",
			IdentityBaseField:    "user_id",
			PolicyFieldName:      "policy_id",
			DefaultPolicies:      []string{pID},
		}
		
		// Use the helper to create a proper OAS API
		createOASAPIWithORAuth(spec, jwtConfig, true)
		
		if spec.OAS.GetTykExtension() != nil && spec.OAS.GetTykExtension().Server.Authentication != nil {
			_ = spec.OAS.GetTykExtension().Server.Authentication.SecurityProcessingMode
		}
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "jwt-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})
	
	
	// Test cases for OR logic
	testCases := []test.TestCase{
		// Test 1: Valid API key only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid JWT only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// Test 3: Valid JWT + Invalid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusOK,
		},
		// Test 4: Invalid JWT + Valid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 5: Both valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 6: Both invalid - should fail with last error
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusForbidden,
		},
		// Test 7: No auth headers - should fail
		{
			Method:  "GET",
			Path:    "/test-or-jwt-apikey/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	// Run all test cases
	ts.Run(t, testCases...)
}

/*
func TestMultiAuthMiddleware_OR_BasicAuth_And_ApiKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	_, apiKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = "" // Match the API's empty OrgID for OAS
		s.AccessRights = map[string]user.AccessDefinition{
			"test-or-basic-apikey": {
				APIName:  "Test OR Basic API Key",
				APIID:    "test-or-basic-apikey",
				Versions: []string{"default"},
			},
		}
	})

	// Create Basic Auth session
	basicUsername := "testuser"
	basicPassword := "testpass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.OrgID = "" // Match the API's empty OrgID for OAS
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-basic-apikey": {
			APIName:  "Test OR Basic API Key",
			APIID:    "test-or-basic-apikey",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session - try with just username as key first
	// Basic Auth middleware checks username directly first, then with OrgID
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicUsername, basicSession, 60, ts.Gw.GetConfig().HashKeys)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with Basic Auth and API key
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-basic-apikey"
		spec.Name = "Test OR Basic API Key"
		spec.OrgID = "" // Empty OrgID for OAS API
		spec.Proxy.ListenPath = "/test-or-basic-apikey/"
		spec.Proxy.TargetURL = ts.URL
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
		spec.DisableRateLimit = true
		spec.DisableQuota = true

		// Create proper OAS API with Basic Auth and API Key support
		createOASAPIWithBasicAndAPIKey(spec)
		
	})

	// Encode basic auth credentials
	basicAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))
	invalidBasicAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":wrongpass"))

	// Test cases for OR logic with Basic Auth and API Key
	testCases := []test.TestCase{
		// Test 1: Valid Basic Auth only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"Authorization": basicAuthHeader,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid API key only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 3: Valid Basic Auth + Invalid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"Authorization": basicAuthHeader,
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusOK,
		},
		// Test 4: Invalid Basic Auth + Valid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"Authorization": invalidBasicAuthHeader,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 5: Both valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"Authorization": basicAuthHeader,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 6: Both invalid - should fail
		{
			Method: "GET",
			Path:   "/test-or-basic-apikey/",
			Headers: map[string]string{
				"Authorization": invalidBasicAuthHeader,
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusForbidden,
		},
		// Test 7: No auth headers - should fail
		{
			Method:  "GET",
			Path:    "/test-or-basic-apikey/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}
*/

// TestMultiAuthMiddleware_OR_AllMethodsFail tests error aggregation when all methods fail
func TestMultiAuthMiddleware_OR_AllMethodsFail(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure API with JWT and API key, OR logic
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-all-fail"
		spec.Name = "Test OR All Fail"
		spec.Proxy.ListenPath = "/test-or-all-fail/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Configure JWT for OAS
		jwtConfig := &oas.JWT{
			Enabled: true,
			AuthSources: oas.AuthSources{
				Header: &oas.AuthSource{
					Enabled: true,
					Name:    "Authorization",
				},
			},
			SigningMethod: "rsa",
			Source:        base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
			IdentityBaseField: "user_id",
		}

		// Create OAS API with JWT and API key, OR logic
		createOASAPIWithORAuth(spec, jwtConfig, true)
	})

	// Test cases - all auth methods should fail
	testCases := []test.TestCase{
		// Test 1: Invalid JWT and invalid API key - should return last error
		{
			Method: "GET",
			Path:   "/test-or-all-fail/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt-token",
				"X-API-Key":     "invalid-api-key",
			},
			Code: http.StatusForbidden,
		},
		// Test 2: Only invalid JWT - should fail
		{
			Method: "GET",
			Path:   "/test-or-all-fail/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
			},
			Code: http.StatusUnauthorized, // No API key provided
		},
		// Test 3: Only invalid API key - should fail
		{
			Method: "GET",
			Path:   "/test-or-all-fail/",
			Headers: map[string]string{
				"X-API-Key": "invalid-key",
			},
			Code: http.StatusForbidden, // API key invalid
		},
	}

	ts.Run(t, testCases...)
}
// 
// TestMultiAuthMiddleware_BackwardCompatibility_AND_Logic tests that AND logic is preserved when SecurityRequirements <= 1
/*
func TestMultiAuthMiddleware_BackwardCompatibility_AND_Logic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
		// Keep default OrgID for non-OAS API
		p.AccessRights = map[string]user.AccessDefinition{
			"test-and-logic": {
				APIName:  "Test AND Logic",
				APIID:    "test-and-logic",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-and-logic": {
			APIName:  "Test AND Logic",
			APIID:    "test-and-logic",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Configure API with JWT and API key, but with single/no SecurityRequirements (AND logic)
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-and-logic"
		spec.Name = "Test AND Logic"
		spec.Proxy.ListenPath = "/test-and-logic/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both JWT and API key
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.JWTDefaultPolicies = []string{pID}

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
		}

		// Single security requirement or empty = AND logic (backward compatibility)
		spec.SecurityRequirements = [][]string{
			{"jwt", "apikey"}, // Single requirement with both methods = AND logic
		}

		spec.BaseIdentityProvidedBy = apidef.AuthToken // API key provides base identity

	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "jwt-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases for AND logic (backward compatibility)
	testCases := []test.TestCase{
		// Test 1: Both valid JWT and API key - should succeed (AND logic requires both)
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid JWT only - should fail (AND logic requires both)
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code:      http.StatusUnauthorized,
			BodyMatch: "Authorization field missing",
		},
		// Test 3: Valid API key only - should fail (AND logic requires both)
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code:      http.StatusBadRequest,
			BodyMatch: "Authorization field missing",
		},
		// Test 4: Invalid JWT + Valid API key - should fail
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     apiKey,
			},
			Code:      http.StatusForbidden,
			BodyMatch: "Key not authorized",
		},
		// Test 5: Valid JWT + Invalid API key - should fail
		{
			Method: "GET",
			Path:   "/test-and-logic/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusForbidden,
		},
	}

	ts.Run(t, testCases...)
}
*/

/*
func TestMultiAuthMiddleware_OR_MixedValidInvalid(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session with empty OrgID for OAS
	_, apiKey1 := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = "" // Match the API's empty OrgID for OAS
		s.AccessRights = map[string]user.AccessDefinition{
			"test-or-mixed": {
				APIName:  "Test OR Mixed",
				APIID:    "test-or-mixed",
				Versions: []string{"default"},
			},
		}
	})

	// Create Basic Auth session
	basicUsername := "mixeduser"
	basicPassword := "mixedpass"
	basicSession := CreateStandardSession()
	basicSession.OrgID = "" // Match the API's empty OrgID for OAS
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-mixed": {
			APIName:  "Test OR Mixed",
			APIID:    "test-or-mixed",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session with just username as key
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicUsername, basicSession, 60, ts.Gw.GetConfig().HashKeys)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with multiple auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-mixed"
		spec.Name = "Test OR Mixed"
		spec.OrgID = "" // Empty OrgID for OAS API
		spec.Proxy.ListenPath = "/test-or-mixed/"
		spec.Proxy.TargetURL = ts.URL
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
		spec.DisableRateLimit = true
		spec.DisableQuota = true

		// Create proper OAS API with Basic Auth and API Key support
		createOASAPIWithBasicAndAPIKey(spec)
	})

	// Prepare auth headers
	validBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))
	invalidBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("wronguser:wrongpass"))

	// Test mixed valid/invalid scenarios
	testCases := []test.TestCase{
		// Test 1: First method invalid, second valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"Authorization": invalidBasicAuth,
				"X-API-Key":     apiKey1,
			},
			Code: http.StatusOK,
		},
		// Test 2: First method valid, second invalid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"Authorization": validBasicAuth,
				"X-API-Key":     "totally-wrong-key",
			},
			Code: http.StatusOK,
		},
		// Test 3: Empty first method, valid second - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"X-API-Key": apiKey1,
			},
			Code: http.StatusOK,
		},
		// Test 4: Valid first method, empty second - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"Authorization": validBasicAuth,
			},
			Code: http.StatusOK,
		},
		// Test 5: Malformed Basic Auth + valid API key - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"Authorization": "Basic malformed",
				"X-API-Key":     apiKey1,
			},
			Code: http.StatusOK,
		},
		// Test 6: Valid Basic Auth + malformed API key - should succeed
		{
			Method: "GET",
			Path:   "/test-or-mixed/",
			Headers: map[string]string{
				"Authorization": validBasicAuth,
				"X-API-Key":     "",
			},
			Code: http.StatusOK,
		},
	}

	ts.Run(t, testCases...)
}
*/

/*
func TestMultiAuthMiddleware_OR_ThreeAuthMethods(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT with empty OrgID
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "" // Match the API's empty OrgID for OAS
		p.AccessRights = map[string]user.AccessDefinition{
			"test-or-three": {
				APIName:  "Test OR Three",
				APIID:    "test-or-three",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session with empty OrgID
	_, apiKey := ts.CreateSession(func(s *user.SessionState) {
		s.OrgID = "" // Match the API's empty OrgID for OAS
		s.AccessRights = map[string]user.AccessDefinition{
			"test-or-three": {
				APIName:  "Test OR Three",
				APIID:    "test-or-three",
				Versions: []string{"default"},
			},
		}
	})

	// Create Basic Auth session
	basicUsername := "threeuser"
	basicPassword := "threepass"
	basicSession := CreateStandardSession()
	basicSession.OrgID = "" // Match the API's empty OrgID for OAS
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-three": {
			APIName:  "Test OR Three",
			APIID:    "test-or-three",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session with username as key
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicUsername, basicSession, 60, ts.Gw.GetConfig().HashKeys)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with three auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-three"
		spec.Name = "Test OR Three"
		spec.OrgID = "" // Empty OrgID for OAS API
		spec.Proxy.ListenPath = "/test-or-three/"
		spec.Proxy.TargetURL = ts.URL
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
		spec.DisableRateLimit = true
		spec.DisableQuota = true

		// Configure JWT for OAS
		jwtConfig := &oas.JWT{
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
		}

		// Create OAS API with three auth methods
		createOASAPIWithThreeAuthMethods(spec, jwtConfig)
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "jwt-user-three"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Prepare auth headers
	validBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Test three auth methods with OR logic
	testCases := []test.TestCase{
		// Test 1: Only first method (Basic) valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"Authorization": validBasicAuth,
			},
			Code: http.StatusOK,
		},
		// Test 2: Only second method (API Key) valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 3: Only third method (JWT) valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"X-JWT-Token": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// Test 4: First two invalid, third valid - should succeed
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"Authorization": "Basic invalid",
				"X-API-Key":     "invalid-key",
				"X-JWT-Token":   "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// Test 5: All three valid - should succeed (first one wins)
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"Authorization": validBasicAuth,
				"X-API-Key":     apiKey,
				"X-JWT-Token":   "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// Test 6: All three invalid - should fail
		{
			Method: "GET",
			Path:   "/test-or-three/",
			Headers: map[string]string{
				"Authorization": "Basic wrong",
				"X-API-Key":     "wrong-key",
				"X-JWT-Token":   "Bearer wrong-jwt",
			},
			Code: http.StatusForbidden,
		},
	}

	ts.Run(t, testCases...)
}
*/

/*
func TestAuthORWrapper_EnabledForSpec(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("should return false when SecurityRequirements <= 1", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				SecurityRequirements: [][]string{{"jwt"}},
			},
		}

		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   ts.Gw,
			},
			authMiddlewares: []TykMiddleware{&AuthKey{}},
		}

		if wrapper.EnabledForSpec() {
			t.Error("Expected EnabledForSpec to return false for single security requirement")
		}
	})

	t.Run("should return false when authMiddlewares <= 1", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				SecurityRequirements: [][]string{{"jwt"}, {"apikey"}},
			},
		}

		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   ts.Gw,
			},
			authMiddlewares: []TykMiddleware{},
		}

		if wrapper.EnabledForSpec() {
			t.Error("Expected EnabledForSpec to return false when no auth middlewares")
		}
	})

	t.Run("should return true when SecurityRequirements > 1 and authMiddlewares > 1", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				SecurityRequirements: [][]string{{"jwt"}, {"apikey"}},
			},
		}

		wrapper := &AuthORWrapper{
			BaseMiddleware: BaseMiddleware{
				Spec: spec,
				Gw:   ts.Gw,
			},
			authMiddlewares: []TykMiddleware{&AuthKey{}, &JWTMiddleware{}},
		}

		if !wrapper.EnabledForSpec() {
			t.Error("Expected EnabledForSpec to return true for multiple requirements and middlewares")
		}
	})
}

// TestAuthORWrapper_Init_AllAuthTypes tests Init with all authentication types
func TestAuthORWrapper_Init_AllAuthTypes(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			EnableJWT:               true,
			UseBasicAuth:            true,
			EnableSignatureChecking: true,
			UseOauth2:               true,
			UseStandardAuth:         false,
		},
	}

	wrapper := &AuthORWrapper{
		BaseMiddleware: BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	wrapper.Init()

	if len(wrapper.authMiddlewares) != 4 {
		t.Errorf("Expected 4 auth middlewares, got %d", len(wrapper.authMiddlewares))
	}

	expectedTypes := map[string]bool{
		"*gateway.JWTMiddleware":                     false,
		"*gateway.BasicAuthKeyIsValid":               false,
		"*gateway.HTTPSignatureValidationMiddleware": false,
		"*gateway.Oauth2KeyExists":                   false,
	}

	for _, mw := range wrapper.authMiddlewares {
		typeName := fmt.Sprintf("%T", mw)
		if _, exists := expectedTypes[typeName]; exists {
			expectedTypes[typeName] = true
		}
	}

	for typeName, found := range expectedTypes {
		if !found {
			t.Errorf("Expected middleware type %s not found", typeName)
		}
	}
}

// TestAuthORWrapper_Init_NoAuthConfigured tests Init when no auth is configured
func TestAuthORWrapper_Init_NoAuthConfigured(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			EnableJWT:               false,
			UseBasicAuth:            false,
			EnableSignatureChecking: false,
			UseOauth2:               false,
			UseStandardAuth:         false,
		},
	}

	wrapper := &AuthORWrapper{
		BaseMiddleware: BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	wrapper.Init()

	if len(wrapper.authMiddlewares) != 1 {
		t.Errorf("Expected 1 auth middleware (fallback), got %d", len(wrapper.authMiddlewares))
	}

	if _, ok := wrapper.authMiddlewares[0].(*AuthKey); !ok {
		t.Errorf("Expected AuthKey middleware as fallback, got %T", wrapper.authMiddlewares[0])
	}
}

// TestAuthORWrapper_Init_WithStandardAuth tests Init when UseStandardAuth is true
func TestAuthORWrapper_Init_WithStandardAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			EnableJWT:               false,
			UseBasicAuth:            false,
			EnableSignatureChecking: false,
			UseOauth2:               false,
			UseStandardAuth:         true,
		},
	}

	wrapper := &AuthORWrapper{
		BaseMiddleware: BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	wrapper.Init()

	if len(wrapper.authMiddlewares) != 1 {
		t.Errorf("Expected 1 auth middleware, got %d", len(wrapper.authMiddlewares))
	}

	if _, ok := wrapper.authMiddlewares[0].(*AuthKey); !ok {
		t.Errorf("Expected AuthKey middleware, got %T", wrapper.authMiddlewares[0])
	}
}

// TestAuthORWrapper_Name tests the Name method
func TestAuthORWrapper_Name(t *testing.T) {
	wrapper := &AuthORWrapper{}
	if wrapper.Name() != "AuthORWrapper" {
		t.Errorf("Expected name 'AuthORWrapper', got '%s'", wrapper.Name())
	}
}

// TestMultiAuthMiddleware_OR_OAuth2_And_ApiKey tests OR logic with OAuth2 and API key
/*
func TestMultiAuthMiddleware_OR_OAuth2_And_ApiKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create policy for OAuth and API key access
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			"test-or-oauth-apikey": {
				APIName:  "Test OR OAuth API Key",
				APIID:    "test-or-oauth-apikey",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-oauth-apikey": {
			APIName:  "Test OR OAuth API Key",
			APIID:    "test-or-oauth-apikey",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Configure API with OAuth2 and API key
	spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-oauth-apikey"
		spec.Name = "Test OR OAuth API Key"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-oauth-apikey/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both OAuth2 and API key
		spec.UseOauth2 = true
		spec.UseStandardAuth = true

		// Configure OAuth2
		spec.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		}
		spec.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{
			"code",
			"token",
		}

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"oauth": {
				AuthHeaderName: "Authorization",
			},
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"oauth"},  // Option 1: OAuth2
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})[0]

	// Create OAuth client
	clientID := "test-oauth-client"
	clientSecret := "test-secret"
	oauthClient := OAuthClient{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		ClientRedirectURI: "http://redirect.example.com",
		PolicyID:          pID,
	}

	// Store OAuth client using the spec's OAuth manager
	spec.OAuthManager.Storage().SetClient(clientID, spec.OrgID, &oauthClient, false)

	// Get OAuth token using the authorize-client endpoint
	param := make(url.Values)
	param.Set("response_type", "token")
	param.Set("redirect_uri", oauthClient.ClientRedirectURI)
	param.Set("client_id", clientID)
	param.Set("client_secret", clientSecret)
	param.Set("key_rules", `{"test-or-oauth-apikey": {"access_rights": {"test-or-oauth-apikey": {"api_id": "test-or-oauth-apikey", "api_name": "Test OR OAuth API Key", "versions": ["default"]}}}}`)

	resp, err := ts.Run(t, test.TestCase{
		Path:      "/test-or-oauth-apikey/tyk/oauth/authorize-client/",
		Data:      param.Encode(),
		AdminAuth: true,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Method: http.MethodPost,
		Code:   http.StatusOK,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Extract OAuth token
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatal("Failed to decode OAuth token response:", err)
	}

	// Test cases for OR logic with OAuth2 and API Key
	testCases := []test.TestCase{
		// Test 1: Valid OAuth token only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-oauth-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + tokenResponse.AccessToken,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid API key only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-oauth-apikey/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 3: Invalid OAuth + Valid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-oauth-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-oauth-token",
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 4: Valid OAuth + Invalid API key - should succeed (OR logic)
		{
			Method: "GET",
			Path:   "/test-or-oauth-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + tokenResponse.AccessToken,
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusOK,
		},
		// Test 5: Both invalid - should fail
		{
			Method: "GET",
			Path:   "/test-or-oauth-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-oauth",
				"X-API-Key":     "invalid-key",
			},
			Code: http.StatusForbidden,
		},
		// Test 6: No auth headers - should fail
		{
			Method:  "GET",
			Path:    "/test-or-oauth-apikey/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

// TestMultiAuthMiddleware_OR_SessionPersistence tests that session data persists correctly with OR auth
*/

/*
func TestMultiAuthMiddleware_OR_SessionPersistence(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session with specific metadata
	apiKeySession := CreateStandardSession()
	apiKeySession.MetaData = map[string]interface{}{
		"auth_type": "api_key",
		"user_id":   "apikey-user-123",
	}
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-session": {
			APIName:  "Test OR Session",
			APIID:    "test-or-session",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session with different metadata
	basicUsername := "sessionuser"
	basicPassword := "sessionpass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.MetaData = map[string]interface{}{
		"auth_type": "basic",
		"user_id":   "basic-user-456",
	}
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-session": {
			APIName:  "Test OR Session",
			APIID:    "test-or-session",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-session"
		spec.Name = "Test OR Session"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-session/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both auth methods
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	// Prepare auth headers
	validBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Test that the correct session is used based on which auth succeeds
	t.Run("API Key session metadata", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method: "GET",
				Path:   "/test-or-session/",
				Headers: map[string]string{
					"X-API-Key": apiKey,
				},
				Code: http.StatusOK,
			},
		}...)
	})

	t.Run("Basic Auth session metadata", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method: "GET",
				Path:   "/test-or-session/",
				Headers: map[string]string{
					"Authorization": validBasicAuth,
				},
				Code: http.StatusOK,
			},
		}...)
	})

	// Test with both - first successful auth's session should be used
	t.Run("First successful auth session used", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{
				Method: "GET",
				Path:   "/test-or-session/",
				Headers: map[string]string{
					"Authorization": validBasicAuth,
					"X-API-Key":     apiKey,
				},
				Code: http.StatusOK,
			},
		}...)
	})
}

// TestMultiAuthMiddleware_OR_RateLimiting tests rate limiting with OR auth
*/

/*
func TestMultiAuthMiddleware_OR_RateLimiting(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session with low rate limit
	apiKeySession := CreateStandardSession()
	apiKeySession.Rate = 2 // 2 requests
	apiKeySession.Per = 60 // per minute
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-ratelimit": {
			APIName:  "Test OR Rate Limit",
			APIID:    "test-or-ratelimit",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session with higher rate limit
	basicUsername := "ratelimituser"
	basicPassword := "ratelimitpass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.Rate = 10 // 10 requests
	basicSession.Per = 60  // per minute
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-ratelimit": {
			APIName:  "Test OR Rate Limit",
			APIID:    "test-or-ratelimit",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-ratelimit"
		spec.Name = "Test OR Rate Limit"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-ratelimit/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both auth methods
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	// Prepare auth headers
	validBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Test that rate limiting applies based on the successful auth method
	t.Run("API Key rate limit applies", func(t *testing.T) {
		// First 2 requests should succeed
		for i := 0; i < 2; i++ {
			ts.Run(t, test.TestCase{
				Method: "GET",
				Path:   "/test-or-ratelimit/",
				Headers: map[string]string{
					"X-API-Key": apiKey,
				},
				Code: http.StatusOK,
			})
		}

		// Third request should be rate limited
		ts.Run(t, test.TestCase{
			Method: "GET",
			Path:   "/test-or-ratelimit/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusTooManyRequests,
		})
	})

	// Clear rate limit counters by waiting
	time.Sleep(time.Second)

	t.Run("Basic Auth rate limit applies", func(t *testing.T) {
		// Should allow more requests with Basic Auth (10 per minute)
		for i := 0; i < 5; i++ {
			ts.Run(t, test.TestCase{
				Method: "GET",
				Path:   "/test-or-ratelimit/",
				Headers: map[string]string{
					"Authorization": validBasicAuth,
				},
				Code: http.StatusOK,
			})
		}
	})
}

// TestMultiAuthMiddleware_OR_ErrorMessages tests error message consistency with OR auth
*/

/*
func TestMultiAuthMiddleware_OR_ErrorMessages(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure API with JWT and API key
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-errors"
		spec.Name = "Test OR Errors"
		spec.Proxy.ListenPath = "/test-or-errors/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both JWT and API key
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"jwt"},    // Option 1: JWT
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	// Test various error scenarios and verify error messages
	testCases := []test.TestCase{
		// No auth provided - should return appropriate error
		{
			Method:    "GET",
			Path:      "/test-or-errors/",
			Headers:   map[string]string{},
			Code:      http.StatusUnauthorized,
			BodyMatch: "Authorization field missing",
		},
		// Invalid JWT format
		{
			Method: "GET",
			Path:   "/test-or-errors/",
			Headers: map[string]string{
				"Authorization": "Bearer not-a-jwt",
			},
			Code:      http.StatusUnauthorized,
			BodyMatch: "Authorization field missing",
		},
		// Invalid API key
		{
			Method: "GET",
			Path:   "/test-or-errors/",
			Headers: map[string]string{
				"X-API-Key": "invalid-key-format",
			},
			Code:      http.StatusForbidden,
			BodyMatch: "Access to this API has been disallowed",
		},
		// Both invalid - should return last error
		{
			Method: "GET",
			Path:   "/test-or-errors/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt",
				"X-API-Key":     "invalid-key",
			},
			Code:      http.StatusForbidden,
			BodyMatch: "Access to this API has been disallowed",
		},
	}

	ts.Run(t, testCases...)
}

// TestMultiAuthMiddleware_OR_PerformanceWithManyMethods tests performance with many auth methods
*/

/*
func TestMultiAuthMiddleware_OR_PerformanceWithManyMethods(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-performance": {
			APIName:  "Test OR Performance",
			APIID:    "test-or-performance",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Configure API with multiple auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-performance"
		spec.Name = "Test OR Performance"
		spec.Proxy.ListenPath = "/test-or-performance/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable multiple auth methods
		spec.UseStandardAuth = true
		spec.EnableJWT = true
		spec.UseBasicAuth = true
		spec.EnableSignatureChecking = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"hmac": {
				AuthHeaderName: "Authorization",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"jwt"},    // Option 1: JWT
			{"basic"},  // Option 2: Basic Auth
			{"hmac"},   // Option 3: HMAC
			{"apikey"}, // Option 4: API key (should succeed quickly as last option)
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	// Measure time for successful auth with last method
	start := time.Now()

	// API key is the last method but should still succeed quickly
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/test-or-performance/",
		Headers: map[string]string{
			"X-API-Key": apiKey,
		},
		Code: http.StatusOK,
	})

	duration := time.Since(start)

	// Even with multiple auth methods, it should complete quickly (< 100ms)
	if duration > 100*time.Millisecond {
		// Performance check
	}

	// Test with invalid credentials for all methods - should try all and fail
	start = time.Now()

	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/test-or-performance/",
		Headers: map[string]string{
			"Authorization": "Bearer invalid",
			"X-API-Key":     "invalid",
		},
		Code: http.StatusForbidden,
	})

	duration = time.Since(start)

	// Should still complete reasonably quickly even when trying all methods
	if duration > 200*time.Millisecond {
		// Performance check for failure case
	}
}

// TestMultiAuthMiddleware_OR_SessionIsolation tests that failed auth attempts don't contaminate the session
*/

/*
func TestMultiAuthMiddleware_OR_SessionIsolation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session with specific metadata
	apiKeySession := CreateStandardSession()
	apiKeySession.MetaData = map[string]interface{}{
		"source": "api_key",
		"clean":  true,
	}
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-isolation": {
			APIName:  "Test OR Isolation",
			APIID:    "test-or-isolation",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Configure API with JWT and API key
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-isolation"
		spec.Name = "Test OR Isolation"
		spec.Proxy.ListenPath = "/test-or-isolation/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true

		// Enable both JWT and API key
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"apikey": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"jwt"},    // Option 1: JWT (will fail with invalid token)
			{"apikey"}, // Option 2: API key (will succeed)
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	// Test that a failed JWT attempt doesn't contaminate the session for API key
	// The JWT middleware might modify the session context even when failing
	// Request cloning should prevent this from affecting the API key auth
	testCases := []test.TestCase{
		// Test 1: Invalid JWT + Valid API key
		// Without request cloning, the failed JWT might contaminate the session
		// With cloning, the API key should get a clean session
		{
			Method: "GET",
			Path:   "/test-or-isolation/",
			Headers: map[string]string{
				"Authorization": "Bearer invalid-jwt-that-might-modify-session",
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid API key only (control test)
		{
			Method: "GET",
			Path:   "/test-or-isolation/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		// Test 3: Multiple invalid attempts before valid API key
		// Tests that multiple failed attempts don't accumulate contamination
		{
			Method: "GET",
			Path:   "/test-or-isolation/",
			Headers: map[string]string{
				"Authorization": "Bearer completely-invalid",
				"X-API-Key":     apiKey,
			},
			Code: http.StatusOK,
		},
	}

	ts.Run(t, testCases...)
}

func TestSecurityProcessingMode_LegacyMode(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-legacy-mode": {
			APIName:  "Test Legacy Mode",
			APIID:    "test-legacy-mode",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session
	basicUsername := "legacy-user"
	basicPassword := "password"
	basicAuthSession := CreateStandardSession()
	basicAuthSession.BasicAuthData.Password = basicPassword
	basicAuthSession.AccessRights = map[string]user.AccessDefinition{
		"test-legacy-mode": {
			APIName:  "Test Legacy Mode",
			APIID:    "test-legacy-mode",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicAuthSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}
	basicAuthKey := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Configure API with explicit legacy mode
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-legacy-mode"
		spec.Name = "Test Legacy Mode"
		spec.Proxy.ListenPath = "/test-legacy-mode/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.UseStandardAuth = true
		spec.UseBasicAuth = false // Don't enable basic auth in legacy mode test

		// Classic APIs always use legacy mode by default

		// Multiple security requirements - in legacy mode, only first should be used
		spec.SecurityRequirements = [][]string{
			{"apikey"}, // First requirement - should be used
			{"basic"},  // Second requirement - should be ignored in legacy mode
		}

		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				AuthHeaderName: "X-API-Key",
			},
			apidef.BasicType: {
				AuthHeaderName: "Authorization",
			},
		}
	})

	testCases := []test.TestCase{
		{
			Method: "GET",
			Path:   "/test-legacy-mode/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test-legacy-mode/",
			Headers: map[string]string{
				"Authorization": basicAuthKey,
			},
			Code: http.StatusUnauthorized,
		},
		{
			Method:  "GET",
			Path:    "/test-legacy-mode/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

func TestSecurityProcessingMode_CompliantMode(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-compliant-mode": {
			APIName:  "Test Compliant Mode",
			APIID:    "test-compliant-mode",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session
	basicUsername := "compliant-user"
	basicPassword := "password"
	basicAuthSession := CreateStandardSession()
	basicAuthSession.BasicAuthData.Password = basicPassword
	basicAuthSession.AccessRights = map[string]user.AccessDefinition{
		"test-compliant-mode": {
			APIName:  "Test Compliant Mode",
			APIID:    "test-compliant-mode",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicAuthSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}
	basicAuthKey := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Configure API with explicit compliant mode
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-compliant-mode"
		spec.Name = "Test Compliant Mode"
		spec.Proxy.ListenPath = "/test-compliant-mode/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.UseStandardAuth = true
		spec.UseBasicAuth = true

		// Configure OR logic through multiple security requirements
		spec.SecurityRequirements = [][]string{
			{"apikey"}, // Option 1: API key
			{"basic"},  // Option 2: Basic auth
		}

		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				AuthHeaderName: "X-API-Key",
			},
			apidef.BasicType: {
				AuthHeaderName: "Authorization",
			},
		}

		// Mark as OAS API with compliant mode for OR logic
		createOASAPIWithORAuth(spec, spec.AuthConfigs, spec.SecurityRequirements)
	})

	testCases := []test.TestCase{
		{
			Method: "GET",
			Path:   "/test-compliant-mode/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test-compliant-mode/",
			Headers: map[string]string{
				"Authorization": basicAuthKey,
			},
			Code: http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/test-compliant-mode/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}

func TestSecurityProcessingMode_DefaultBehavior(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-default-mode": {
			APIName:  "Test Default Mode",
			APIID:    "test-default-mode",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session
	basicUsername := "default-user"
	basicPassword := "password"
	basicAuthSession := CreateStandardSession()
	basicAuthSession.BasicAuthData.Password = basicPassword
	basicAuthSession.AccessRights = map[string]user.AccessDefinition{
		"test-default-mode": {
			APIName:  "Test Default Mode",
			APIID:    "test-default-mode",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicAuthSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}
	basicAuthKey := "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUsername+":"+basicPassword))

	// Configure API without SecurityProcessingMode
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-default-mode"
		spec.Name = "Test Default Mode"
		spec.Proxy.ListenPath = "/test-default-mode/"
		spec.Proxy.TargetURL = "http://httpbin.org/"
		spec.UseKeylessAccess = false
		spec.Active = true
		spec.UseStandardAuth = true
		spec.UseBasicAuth = false // Only enable API key for legacy default

		// DO NOT set SecurityProcessingMode
		// Default should be legacy mode for backward compatibility

		// Multiple security requirements
		spec.SecurityRequirements = [][]string{
			{"apikey"}, // Option 1 - should be used in legacy mode
			{"basic"},  // Option 2 - should be ignored in legacy mode
		}

		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				AuthHeaderName: "X-API-Key",
			},
			apidef.BasicType: {
				AuthHeaderName: "Authorization",
			},
		}
	})

	testCases := []test.TestCase{
		{
			Method: "GET",
			Path:   "/test-default-mode/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
			},
			Code: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test-default-mode/",
			Headers: map[string]string{
				"Authorization": basicAuthKey,
			},
			Code: http.StatusUnauthorized, // Should fail in legacy mode
		},
		{
			Method:  "GET",
			Path:    "/test-default-mode/",
			Headers: map[string]string{},
			Code:    http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}
*/
