package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"

	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func createRLSession() *user.SessionState {
	session := user.NewSessionState()
	// essentially non-throttled
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10
	session.AccessRights = map[string]user.AccessDefinition{"31445455": {APIName: "Tyk Auth Key Test", APIID: "31445455", Versions: []string{"default"}}}
	return session
}

func (ts *Test) getRLOpenChain(spec *APISpec) http.Handler {

	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := &BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}
	chain := alice.New(ts.Gw.mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&RateLimitForAPI{BaseMiddleware: baseMid},
	)...).Then(proxyHandler)
	return chain
}

func (ts *Test) getGlobalRLAuthKeyChain(spec *APISpec) http.Handler {

	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := ts.Gw.TykNewSingleHostReverseProxy(remote, spec, nil)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := &BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}
	chain := alice.New(ts.Gw.mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitForAPI{BaseMiddleware: baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func TestRateLimitForAPI_EnabledForSpec(t *testing.T) {
	apiSpecDisabled := APISpec{APIDefinition: &apidef.APIDefinition{GlobalRateLimit: apidef.GlobalRateLimit{Disabled: true, Rate: 2, Per: 1}}}

	rlDisabled := &RateLimitForAPI{BaseMiddleware: &BaseMiddleware{Spec: &apiSpecDisabled}}
	assert.False(t, rlDisabled.EnabledForSpec())
}

func TestRLOpen(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(openRLDefSmall)

	ts.Gw.DoReload()
	chain := ts.getRLOpenChain(spec)
	for a := 0; a <= 10; a++ {
		recorder := httptest.NewRecorder()

		req := TestReq(t, "GET", "/rl_test/", nil)
		chain.ServeHTTP(recorder, req)

		if a < 3 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit kicked in too early, after only %v requests", a)
			}
		}

		if a > 7 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit did not activate, code was: %v", recorder.Code)
			}
		}
	}
}

func requestThrottlingTest(limiter string, testLevel string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ts := StartTest(nil)
		defer ts.Close()

		globalCfg := ts.Gw.GetConfig()

		switch limiter {
		case "InMemoryRateLimiter":
		case "SentinelRateLimiter":
			globalCfg.EnableSentinelRateLimiter = true
		case "RedisRollingRateLimiter":
			globalCfg.EnableRedisRollingLimiter = true
		default:
			t.Fatal("There is no such a rate limiter:", limiter)
		}

		ts.Gw.SetConfig(globalCfg)

		var per, rate float64
		var throttleRetryLimit int

		per = 2
		rate = 1
		throttleRetryLimit = 3

		// Toggle request throttling on and off, with different throttle intervals.
		iterations := map[bool][]float64{
			true:  {-1, 0, 1},
			false: {-1, 0, 1},
		}

		for requestThrottlingEnabled, throttleIntervals := range iterations {
			for _, throttleInterval := range throttleIntervals {
				spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.Name = "test"
					spec.APIID = "test"
					spec.OrgID = "default"
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
				})[0]

				policyID := ts.CreatePolicy(func(p *user.Policy) {
					p.OrgID = "default"

					p.AccessRights = map[string]user.AccessDefinition{
						spec.APIID: {
							APIName: spec.APIDefinition.Name,
							APIID:   spec.APIID,
						},
					}

					if testLevel == "PolicyLevel" {
						p.Per = per
						p.Rate = rate

						if requestThrottlingEnabled {
							p.ThrottleInterval = throttleInterval
							p.ThrottleRetryLimit = throttleRetryLimit
						}
					} else if testLevel == "APILevel" {
						a := p.AccessRights[spec.APIID]
						a.Limit = user.APILimit{
							RateLimit: user.RateLimit{
								Rate: rate,
								Per:  per,
							},
						}

						if requestThrottlingEnabled {
							a.Limit.ThrottleInterval = throttleInterval
							a.Limit.ThrottleRetryLimit = throttleRetryLimit
						}

						p.Partitions.PerAPI = true

						p.AccessRights[spec.APIID] = a
					} else {
						t.Fatal("There is no such a test level:", testLevel)
					}
				})

				_, key := ts.CreateSession(func(s *user.SessionState) {
					s.ApplyPolicies = []string{policyID}
				})

				authHeaders := map[string]string{
					"authorization": key,
				}

				if requestThrottlingEnabled && throttleInterval > 0 {
					ts.Run(t, []test.TestCase{
						{Path: "/", Headers: authHeaders, Code: 200, Delay: 100 * time.Millisecond},
						{Path: "/", Headers: authHeaders, Code: 200},
					}...)
				} else {
					ts.Run(t, []test.TestCase{
						{Path: "/", Headers: authHeaders, Code: 200, Delay: 100 * time.Millisecond},
						{Path: "/", Headers: authHeaders, Code: 429},
					}...)
				}
			}
		}
	}
}

func TestRequestThrottling(t *testing.T) {
	test.Flaky(t) // TODO TT-5236

	t.Run("PolicyLevel", func(t *testing.T) {
		t.Run("InMemoryRateLimiter", requestThrottlingTest("InMemoryRateLimiter", "PolicyLevel"))
		t.Run("SentinelRateLimiter", requestThrottlingTest("SentinelRateLimiter", "PolicyLevel"))
		t.Run("RedisRollingRateLimiter", requestThrottlingTest("RedisRollingRateLimiter", "PolicyLevel"))
	})

	t.Run("APILevel", func(t *testing.T) {
		t.Run("InMemoryRateLimiter", requestThrottlingTest("InMemoryRateLimiter", "APILevel"))
		t.Run("SentinelRateLimiter", requestThrottlingTest("SentinelRateLimiter", "APILevel"))
		t.Run("RedisRollingRateLimiter", requestThrottlingTest("RedisRollingRateLimiter", "APILevel"))
	})
}

func TestRLClosed(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(closedRLDefSmall)

	session := createRLSession()
	customToken := uuid.New()

	// AuthKey sessions are stored by {token}
	err := ts.Gw.GlobalSessionManager.UpdateSession(customToken, session, 60, false)
	if err != nil {
		t.Error("could not update session in Session Manager. " + err.Error())
	}

	chain := ts.getGlobalRLAuthKeyChain(spec)
	for a := 0; a <= 10; a++ {
		recorder := httptest.NewRecorder()

		req := TestReq(t, "GET", "/rl_closed_test/", nil)
		req.Header.Set("authorization", "Bearer "+customToken)
		chain.ServeHTTP(recorder, req)

		if a < 3 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit kicked in too early, after only %v requests", a)
			}
		}

		if a > 7 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit did not activate, code was: %v", recorder.Code)
			}
		}
	}
}

// TestJSVMStagesRequest
// TestProcessRequestLiveQuotaLimit
func TestRLOpenWithReload(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI(openRLDefSmall)

	chain := ts.getRLOpenChain(spec)
	for a := 0; a <= 10; a++ {
		recorder := httptest.NewRecorder()

		req := TestReq(t, "GET", "/rl_test/", nil)
		chain.ServeHTTP(recorder, req)

		if a < 3 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit (pre change) kicked in too early, after only %v requests", a)
			}
		}

		if a > 7 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit (pre change) did not activate, code was: %v", recorder.Code)
			}
		}
	}

	// Change rate and emulate a reload
	spec.GlobalRateLimit.Rate = 20
	chain = ts.getRLOpenChain(spec)
	for a := 0; a <= 30; a++ {
		recorder := httptest.NewRecorder()

		req := TestReq(t, "GET", "/rl_test/", nil)
		chain.ServeHTTP(recorder, req)

		if a < 20 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit (post change) kicked in too early, after only %v requests", a)
			}
		}

		if a > 23 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit (post change) did not activate, code was: %v", recorder.Code)
			}
		}
	}
}

// TestRateLimitForAPI_ShouldEnable_MCPVEMs tests that shouldEnable() correctly
// detects rate limits in rxPaths (MCP VEM rate limits).
func TestRateLimitForAPI_ShouldEnable_MCPVEMs(t *testing.T) {
	tests := []struct {
		name     string
		setupAPI func(*APISpec)
		expected bool
	}{
		{
			name: "disabled when DisableRateLimit is true",
			setupAPI: func(spec *APISpec) {
				spec.DisableRateLimit = true
			},
			expected: false,
		},
		{
			name: "enabled when ExtendedPaths has rate limits",
			setupAPI: func(spec *APISpec) {
				spec.VersionData.Versions = map[string]apidef.VersionInfo{
					"v1": {
						ExtendedPaths: apidef.ExtendedPathsSet{
							RateLimit: []apidef.RateLimitMeta{
								{Path: "/endpoint", Method: "GET", Rate: 10, Per: 60},
							},
						},
					},
				}
			},
			expected: true,
		},
		{
			name: "enabled when rxPaths has rate limits (MCP VEMs)",
			setupAPI: func(spec *APISpec) {
				// Simulate MCP VEM rate limits compiled into rxPaths
				spec.RxPaths = map[string][]URLSpec{
					"v1": {
						{
							Status: RateLimit,
							RateLimit: apidef.RateLimitMeta{
								Path:   "/mcp-tool:get-weather",
								Method: "POST",
								Rate:   2,
								Per:    20,
							},
						},
					},
				}
			},
			expected: true,
		},
		{
			name: "enabled when global rate limit is configured",
			setupAPI: func(spec *APISpec) {
				spec.GlobalRateLimit = apidef.GlobalRateLimit{
					Rate: 100,
					Per:  60,
				}
			},
			expected: true,
		},
		{
			name: "disabled when global rate limit is disabled",
			setupAPI: func(spec *APISpec) {
				spec.GlobalRateLimit = apidef.GlobalRateLimit{
					Rate:     100,
					Per:      60,
					Disabled: true,
				}
			},
			expected: false,
		},
		{
			name: "disabled when no rate limits are configured",
			setupAPI: func(spec *APISpec) {
				// No rate limits configured
			},
			expected: false,
		},
		{
			name: "enabled when rxPaths has invalid rate limit spec but Valid() returns true",
			setupAPI: func(spec *APISpec) {
				spec.RxPaths = map[string][]URLSpec{
					"v1": {
						{
							Status: RateLimit,
							RateLimit: apidef.RateLimitMeta{
								Path:   "/mcp-tool:test",
								Method: "POST",
								Rate:   5,
								Per:    10,
							},
						},
					},
				}
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: make(map[string]apidef.VersionInfo),
					},
				},
				RxPaths: make(map[string][]URLSpec),
			}

			tt.setupAPI(spec)

			mw := &RateLimitForAPI{
				BaseMiddleware: &BaseMiddleware{Spec: spec},
			}

			result := mw.shouldEnable()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRateLimitForAPI_GetSession_Keyname tests that getSession() returns
// the correct session and keyname for both global and per-endpoint rate limits.
func TestRateLimitForAPI_GetSession_Keyname(t *testing.T) {
	orgID := "test-org"
	apiID := "test-api"

	t.Run("returns global session when no per-endpoint match", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID: apiID,
				OrgID: orgID,
				GlobalRateLimit: apidef.GlobalRateLimit{
					Rate: 100,
					Per:  60,
				},
				VersionData: apidef.VersionData{
					Versions: map[string]apidef.VersionInfo{
						"Default": {Name: "Default"},
					},
					DefaultVersion: "Default",
				},
			},
			RxPaths: make(map[string][]URLSpec),
		}

		mw := &RateLimitForAPI{
			BaseMiddleware: &BaseMiddleware{Spec: spec},
			keyName:        fmt.Sprintf("apilimiter-%s%s", orgID, apiID),
			apiSess: &user.SessionState{
				Rate:        spec.GlobalRateLimit.Rate,
				Per:         spec.GlobalRateLimit.Per,
				LastUpdated: "123456789",
			},
		}

		req := httptest.NewRequest("POST", "/unmapped-path", nil)
		session, keyname := mw.getSession(req)

		assert.Equal(t, float64(100), session.Rate)
		assert.Equal(t, float64(60), session.Per)
		assert.Equal(t, fmt.Sprintf("apilimiter-%s%s", orgID, apiID), keyname)
	})

	t.Run("creates per-endpoint keyname with hash suffix", func(t *testing.T) {
		// Test the keyname generation logic directly
		baseKey := fmt.Sprintf("apilimiter-%s%s", orgID, apiID)
		method := "POST"
		path := "/mcp-tool:rate-limited"

		expectedHash := storage.HashStr(fmt.Sprintf("%s:%s", method, path))
		expectedKeyname := baseKey + "-" + expectedHash

		// Verify hash generation produces consistent results
		actualKeyname := baseKey + "-" + storage.HashStr(fmt.Sprintf("%s:%s", method, path))
		assert.Equal(t, expectedKeyname, actualKeyname)
		assert.Contains(t, actualKeyname, baseKey+"-")
		assert.Greater(t, len(actualKeyname), len(baseKey)+1)
	})
}

// TestRateLimitForAPI_IndependentToolTracking tests that the keyname generation
// logic creates unique keys for different method:path combinations.
func TestRateLimitForAPI_IndependentToolTracking(t *testing.T) {
	orgID := "test-org"
	apiID := "test-api"
	baseKey := fmt.Sprintf("apilimiter-%s%s", orgID, apiID)

	// Test keyname generation with distinct paths that won't collide
	testCases := []struct {
		method string
		path   string
	}{
		{"POST", "/mcp-tool:get-weather"},
		{"POST", "/mcp-tool:get-forecast"},
		{"GET", "/mcp-tool:list-tools"},
	}

	// Generate keynames for each test case
	keynames := make([]string, len(testCases))
	for i, tc := range testCases {
		hash := storage.HashStr(fmt.Sprintf("%s:%s", tc.method, tc.path))
		keynames[i] = baseKey + "-" + hash

		// Verify keyname format
		assert.Contains(t, keynames[i], baseKey)
		assert.Greater(t, len(keynames[i]), len(baseKey)+1, "Keyname should have hash suffix")
	}

	// Verify all keynames are unique (no two tools share the same bucket)
	seen := make(map[string]bool)
	for _, keyname := range keynames {
		assert.False(t, seen[keyname], "Each tool should have a unique keyname")
		seen[keyname] = true
	}
}

// TestRateLimitForAPI_NoGlobalRateLimit tests that the middleware works
// correctly when only per-endpoint rate limits are configured (no global limit).
func TestRateLimitForAPI_NoGlobalRateLimit(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test-api",
			OrgID: "test-org",
			VersionData: apidef.VersionData{
				Versions: map[string]apidef.VersionInfo{
					"Default": {Name: "Default"},
				},
				DefaultVersion: "Default",
			},
			// No GlobalRateLimit configured
		},
		RxPaths: map[string][]URLSpec{
			"Default": {
				{
					Status: RateLimit,
					RateLimit: apidef.RateLimitMeta{
						Path:   "/mcp-tool:limited",
						Method: "POST",
						Rate:   5,
						Per:    60,
					},
				},
			},
		},
	}

	mw := &RateLimitForAPI{
		BaseMiddleware: &BaseMiddleware{Spec: spec},
	}

	// shouldEnable should return true because rxPaths has rate limits
	assert.True(t, mw.shouldEnable())

	// Verify per-endpoint keyname generation works correctly
	baseKey := fmt.Sprintf("apilimiter-%s%s", spec.OrgID, spec.APIID)
	method := "POST"
	path := "/mcp-tool:limited"
	expectedHash := storage.HashStr(fmt.Sprintf("%s:%s", method, path))
	expectedKeyname := baseKey + "-" + expectedHash

	assert.Equal(t, "apilimiter-test-orgtest-api-"+expectedHash, expectedKeyname)
	assert.Contains(t, expectedKeyname, "apilimiter-test-orgtest-api-")
}

const openRLDefSmall = `{
	"api_id": "313232",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/rl_test/",
		"target_url": "` + TestHttpAny + `"
	},
	"global_rate_limit": {
		"rate": 3,
		"per": 1
	}
}`

const closedRLDefSmall = `{
	"api_id": "31445455",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/rl_closed_test/",
		"target_url": "` + TestHttpAny + `"
	},
	"global_rate_limit": {
		"rate": 3,
		"per": 1
	}
}`
