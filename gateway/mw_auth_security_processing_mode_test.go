package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

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
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.UseBasicAuth = false  // Don't enable basic auth in legacy mode test

		// Explicitly set legacy mode
		spec.SecurityProcessingMode = "legacy"

		// Multiple security requirements - in legacy mode, only first should be used
		spec.SecurityRequirements = [][]string{
			{"apikey"},  // First requirement - should be used
			{"basic"},   // Second requirement - should be ignored in legacy mode
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
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.UseBasicAuth = true

		// Explicitly set compliant mode
		spec.SecurityProcessingMode = "compliant"

		// Multiple security requirements - in compliant mode, OR logic applies
		spec.SecurityRequirements = [][]string{
			{"apikey"},  // Option 1: API key
			{"basic"},   // Option 2: Basic auth
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
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.UseBasicAuth = false  // Only enable API key for legacy default

		// DO NOT set SecurityProcessingMode
		// Default should be legacy mode for backward compatibility

		// Multiple security requirements
		spec.SecurityRequirements = [][]string{
			{"apikey"},  // Option 1 - should be used in legacy mode
			{"basic"},   // Option 2 - should be ignored in legacy mode
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
			Code: http.StatusUnauthorized,  // Should fail in legacy mode
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