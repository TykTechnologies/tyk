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
				SecuritySchemes:        oas.SecuritySchemes{},
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
		UseParam:       false,
		DisableHeader:  false,
	}

	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"basic": {
			AuthHeaderName: "Authorization",
		},
		"authToken": {
			AuthHeaderName: "X-API-Key",
			DisableHeader:  false,
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
		UseParam:       false,
		DisableHeader:  false,
	}

	spec.AuthConfigs = map[string]apidef.AuthConfig{
		"jwt": {
			AuthHeaderName: "Authorization",
			DisableHeader:  false,
		},
		"basic": {
			AuthHeaderName: "Authorization",
		},
		"authToken": {
			AuthHeaderName: "X-API-Key",
			DisableHeader:  false,
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
			Enabled:           true,
			Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
			SigningMethod:     "rsa",
			IdentityBaseField: "user_id",
			PolicyFieldName:   "policy_id",
			DefaultPolicies:   []string{pID},
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
			SigningMethod:     "rsa",
			Source:            base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey)),
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
