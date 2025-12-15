package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// TestKeyInactiveWithoutPolicy tests the scenario where a key without policy
// is set to inactive via API and should be rejected by the gateway.
// This is a regression test for TT-16296.
func TestKeyInactiveWithoutPolicy(t *testing.T) {
	// Disable session cache to ensure we always read fresh data from storage
	conf := func(globalConf *config.Config) {
		globalConf.LocalSessionCache.DisableCacheSessionState = true
	}

	ts := StartTest(conf)
	defer ts.Close()

	// Create API that requires authentication
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(api)

	// Step 1: Create API KEY without POLICY
	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		// Ensure no policies are applied
		s.ApplyPolicies = nil
	})

	authHeader := map[string]string{"Authorization": key}

	// Step 2: Send traffic - should succeed
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: authHeader,
		Code:    http.StatusOK,
	})

	// Step 3: Update key to set is_inactive: true
	hashKeys := ts.Gw.GetConfig().HashKeys
	hashedKey := storage.HashKey(key, hashKeys)

	// Get current session and set it to inactive
	session, _ := ts.Gw.GlobalSessionManager.SessionDetail("default", hashedKey, true)
	session.IsInactive = true

	err := ts.Gw.GlobalSessionManager.UpdateSession(hashedKey, &session, 60, true)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	// Step 4: Send traffic - should be rejected with 403 Forbidden
	ts.Run(t, test.TestCase{
		Path:      "/",
		Headers:   authHeader,
		Code:      http.StatusForbidden,
		BodyMatch: "Key is inactive",
	})
}

// TestKeyInactiveWithoutPolicyWithCache tests the same scenario but with
// session cache enabled to ensure cache invalidation works correctly.
func TestKeyInactiveWithoutPolicyWithCache(t *testing.T) {
	// Enable session cache (default behavior)
	conf := func(globalConf *config.Config) {
		globalConf.LocalSessionCache.DisableCacheSessionState = false
	}

	ts := StartTest(conf)
	defer ts.Close()

	// Create API that requires authentication
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(api)

	// Step 1: Create API KEY without POLICY
	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		// Ensure no policies are applied
		s.ApplyPolicies = nil
	})

	authHeader := map[string]string{"Authorization": key}

	// Step 2: Send traffic - should succeed (this also caches the session)
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: authHeader,
		Code:    http.StatusOK,
	})

	// Step 3: Update key to set is_inactive: true
	hashKeys := ts.Gw.GetConfig().HashKeys
	hashedKey := storage.HashKey(key, hashKeys)

	// Get current session and set it to inactive
	session, _ := ts.Gw.GlobalSessionManager.SessionDetail("default", hashedKey, true)
	session.IsInactive = true

	err := ts.Gw.GlobalSessionManager.UpdateSession(hashedKey, &session, 60, true)
	if err != nil {
		t.Fatalf("Failed to update session: %v", err)
	}

	// Flush the session cache to simulate cache invalidation that happens
	// when keys are updated via the API
	cacheKey := key
	if hashKeys {
		cacheKey = storage.HashStr(key, storage.HashMurmur64)
	}
	ts.Gw.SessionCache.Delete(cacheKey)

	// Step 4: Send traffic - should be rejected with 403 Forbidden
	ts.Run(t, test.TestCase{
		Path:      "/",
		Headers:   authHeader,
		Code:      http.StatusForbidden,
		BodyMatch: "Key is inactive",
	})
}
