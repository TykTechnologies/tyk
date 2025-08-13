package gateway

import (
	"net/http"
	"testing"
	
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestORAuthSimple(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create two different API keys
	session1 := CreateStandardSession()
	session1.AccessRights = map[string]user.AccessDefinition{
		"test-or": {
			APIName:  "Test OR API", 
			APIID:    "test-or",
			Versions: []string{"default"},
		},
	}
	
	apiKey1 := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *session1
	})

	session2 := CreateStandardSession()
	session2.AccessRights = map[string]user.AccessDefinition{
		"test-or": {
			APIName:  "Test OR API", 
			APIID:    "test-or",
			Versions: []string{"default"},
		},
	}
	
	apiKey2 := CreateSession(ts.Gw, func(s *user.SessionState) {
		*s = *session2
	})

	// Configure API to use standard auth
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test-or"
		spec.Name = "Test OR API"
		spec.Proxy.ListenPath = "/test-or/"
		spec.UseKeylessAccess = false
		
		// Enable standard auth (API key)
		spec.UseStandardAuth = true
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			"authToken": {
				AuthHeaderName: "X-API-Key",
			},
		}
		
		// This should still work with single auth method
		spec.BaseIdentityProvidedBy = apidef.AuthToken
	})

	// Test cases - basic functionality first
	testCases := []test.TestCase{
		// Test 1: Valid API key 1 - should succeed
		{
			Method: "GET",
			Path:   "/test-or/",
			Headers: map[string]string{
				"X-API-Key": apiKey1,
			},
			Code: http.StatusOK,
		},
		// Test 2: Valid API key 2 - should succeed
		{
			Method: "GET",
			Path:   "/test-or/",
			Headers: map[string]string{
				"X-API-Key": apiKey2,
			},
			Code: http.StatusOK,
		},
		// Test 3: Invalid API key - should fail
		{
			Method: "GET",
			Path:   "/test-or/",
			Headers: map[string]string{
				"X-API-Key": "invalid",
			},
			Code: http.StatusForbidden,
		},
		// Test 4: No API key - should fail
		{
			Method: "GET",
			Path:   "/test-or/",
			Code: http.StatusUnauthorized,
		},
	}

	ts.Run(t, testCases...)
}