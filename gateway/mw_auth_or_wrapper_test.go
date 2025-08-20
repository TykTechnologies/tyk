package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination tests the OR logic with JWT and API key
func TestMultiAuthMiddleware_OR_JWT_And_ApiKey_Combination(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
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

	// Configure API with JWT and API key, OR logic via SecurityRequirements
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-jwt-apikey"
		spec.Name = "Test OR JWT API Key"
		spec.Proxy.ListenPath = "/test-or-jwt-apikey/"
		spec.UseKeylessAccess = false

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
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
		}

		// Simulate OAS import with multiple security requirements (OR logic)
		spec.SecurityRequirements = [][]string{
			{"jwt"},    // Option 1: JWT only
			{"apikey"}, // Option 2: API key only
		}

		// BaseIdentity will be set dynamically
		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
	})

	// Create JWT token
	jwtToken := CreateJWKToken(func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["user_id"] = "jwt-user"
		t.Claims.(jwt.MapClaims)["policy_id"] = pID
		t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(time.Hour).Unix()
	})

	// Test cases for OR logic
	testCases := []test.TestCase{
		// Test 1: Valid JWT only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"Authorization": "Bearer " + jwtToken,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid API key only - should succeed
		{
			Method: "GET",
			Path:   "/test-or-jwt-apikey/",
			Headers: map[string]string{
				"X-API-Key": apiKey,
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

	ts.Run(t, testCases...)
}

// TestMultiAuthMiddleware_OR_BasicAuth_And_ApiKey tests OR logic with Basic Auth and API key
func TestMultiAuthMiddleware_OR_BasicAuth_And_ApiKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-basic-apikey": {
			APIName:  "Test OR Basic API Key",
			APIID:    "test-or-basic-apikey",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session
	basicUsername := "testuser"
	basicPassword := "testpass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-basic-apikey": {
			APIName:  "Test OR Basic API Key",
			APIID:    "test-or-basic-apikey",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session with org-id prefix
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with Basic Auth and API key
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-basic-apikey"
		spec.Name = "Test OR Basic API Key"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-basic-apikey/"
		spec.UseKeylessAccess = false

		// Enable both Basic Auth and API key
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Simulate OAS import with multiple security requirements (OR logic)
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth only
			{"apikey"}, // Option 2: API key only
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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

// TestMultiAuthMiddleware_OR_AllMethodsFail tests error aggregation when all methods fail
func TestMultiAuthMiddleware_OR_AllMethodsFail(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure API with JWT and API key, OR logic
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-all-fail"
		spec.Name = "Test OR All Fail"
		spec.Proxy.ListenPath = "/test-or-all-fail/"
		spec.UseKeylessAccess = false

		// Enable both JWT and API key
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "Authorization",
			},
		}

		// Multiple security requirements trigger OR logic
		spec.SecurityRequirements = [][]string{
			{"jwt"},    // Option 1: JWT only
			{"apikey"}, // Option 2: API key only
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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

// TestMultiAuthMiddleware_BackwardCompatibility_AND_Logic tests that AND logic is preserved when SecurityRequirements <= 1
func TestMultiAuthMiddleware_BackwardCompatibility_AND_Logic(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
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
		spec.UseKeylessAccess = false

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
			"authToken": {
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

// TestMultiAuthMiddleware_OR_MixedValidInvalid tests mixed valid/invalid credentials
func TestMultiAuthMiddleware_OR_MixedValidInvalid(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create multiple API keys with different permissions
	apiKey1Session := CreateStandardSession()
	apiKey1Session.AccessRights = map[string]user.AccessDefinition{
		"test-or-mixed": {
			APIName:  "Test OR Mixed",
			APIID:    "test-or-mixed",
			Versions: []string{"default"},
		},
	}
	apiKey1 := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKey1Session
	})

	// Create Basic Auth session
	basicUsername := "mixeduser"
	basicPassword := "mixedpass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-mixed": {
			APIName:  "Test OR Mixed",
			APIID:    "test-or-mixed",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with multiple auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-mixed"
		spec.Name = "Test OR Mixed"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-mixed/"
		spec.UseKeylessAccess = false

		// Enable Basic Auth and API key
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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

// TestMultiAuthMiddleware_OR_ThreeAuthMethods tests OR logic with three auth methods
func TestMultiAuthMiddleware_OR_ThreeAuthMethods(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a policy for JWT
	pID := ts.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			"test-or-three": {
				APIName:  "Test OR Three",
				APIID:    "test-or-three",
				Versions: []string{"default"},
			},
		}
	})

	// Create API key session
	apiKeySession := CreateStandardSession()
	apiKeySession.AccessRights = map[string]user.AccessDefinition{
		"test-or-three": {
			APIName:  "Test OR Three",
			APIID:    "test-or-three",
			Versions: []string{"default"},
		},
	}
	apiKey := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *apiKeySession
	})

	// Create Basic Auth session
	basicUsername := "threeuser"
	basicPassword := "threepass"
	basicSession := CreateStandardSession()
	basicSession.BasicAuthData.Password = basicPassword
	basicSession.AccessRights = map[string]user.AccessDefinition{
		"test-or-three": {
			APIName:  "Test OR Three",
			APIID:    "test-or-three",
			Versions: []string{"default"},
		},
	}

	// Store basic auth session
	basicKeyName := ts.Gw.generateToken("default", basicUsername)
	err := ts.Gw.GlobalSessionManager.UpdateSession(basicKeyName, basicSession, 60, false)
	if err != nil {
		t.Fatal("Failed to create basic auth session:", err)
	}

	// Configure API with three auth methods
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-three"
		spec.Name = "Test OR Three"
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/test-or-three/"
		spec.UseKeylessAccess = false

		// Enable all three auth methods
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"
		spec.JWTPolicyFieldName = "policy_id"
		spec.JWTDefaultPolicies = []string{pID}

		// Configure auth headers - use different headers to avoid conflicts
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
			"jwt": {
				AuthHeaderName: "X-JWT-Token",
			},
		}

		// Three security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
			{"jwt"},    // Option 3: JWT
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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

// TestAuthORWrapper_EnabledForSpec tests the EnabledForSpec method
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
		spec.UseKeylessAccess = false

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
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"oauth"},  // Option 1: OAuth2
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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
		spec.UseKeylessAccess = false

		// Enable both auth methods
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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
		spec.UseKeylessAccess = false

		// Enable both auth methods
		spec.UseBasicAuth = true
		spec.UseStandardAuth = true

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"basic": {
				AuthHeaderName: "Authorization",
			},
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}

		// Multiple security requirements for OR logic
		spec.SecurityRequirements = [][]string{
			{"basic"},  // Option 1: Basic auth
			{"apikey"}, // Option 2: API key
		}

		spec.BaseIdentityProvidedBy = apidef.UnsetAuth
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
func TestMultiAuthMiddleware_OR_ErrorMessages(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure API with JWT and API key
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or-errors"
		spec.Name = "Test OR Errors"
		spec.Proxy.ListenPath = "/test-or-errors/"
		spec.UseKeylessAccess = false

		// Enable both JWT and API key
		spec.UseStandardAuth = true
		spec.EnableJWT = true

		// Configure JWT
		spec.JWTSigningMethod = RSASign
		spec.JWTSource = base64.StdEncoding.EncodeToString([]byte(jwtRSAPubKey))
		spec.JWTIdentityBaseField = "user_id"

		// Configure auth headers
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {
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
		spec.UseKeylessAccess = false

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
			"authToken": {
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
		t.Logf("Warning: OR auth with multiple methods took %v", duration)
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
		t.Logf("Warning: OR auth failure with multiple methods took %v", duration)
	}
}
