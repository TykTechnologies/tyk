package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/drl"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGetAccessDefinitionByAPIIDOrSession(t *testing.T) {
	api := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "api",
		},
	}

	t.Run("should return error when api is missing in access rights", func(t *testing.T) {
		sessionWithMissingAPI := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"another-api": {},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithMissingAPI, api)
		assert.Nil(t, accessDef)
		assert.Equal(t, "", allowanceScope)
		assert.Error(t, err)
		assert.Equal(t, "unexpected apiID", err.Error())
	})

	t.Run("should return access definition from session when limits for api are not defined", func(t *testing.T) {
		sessionWithoutAPILimits := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"api": {
					Limit: user.APILimit{},
				},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithoutAPILimits, api)
		assert.Equal(t, &user.AccessDefinition{
			Limit: user.APILimit{
				QuotaMax:         int64(1),
				QuotaRenewalRate: int64(1),
				QuotaRenews:      int64(1),
				RateLimit: user.RateLimit{
					Rate: 1.0,
					Per:  1.0,
				},
				ThrottleInterval:   1.0,
				ThrottleRetryLimit: 1.0,
				MaxQueryDepth:      1.0,
			},
		}, accessDef)
		assert.Equal(t, "", allowanceScope)
		assert.NoError(t, err)
	})

	t.Run("should return access definition with api limits", func(t *testing.T) {
		sessionWithAPILimits := &user.SessionState{
			QuotaMax:           int64(1),
			QuotaRenewalRate:   int64(1),
			QuotaRenews:        int64(1),
			Rate:               1.0,
			Per:                1.0,
			ThrottleInterval:   1.0,
			ThrottleRetryLimit: 1.0,
			MaxQueryDepth:      1.0,
			AccessRights: map[string]user.AccessDefinition{
				"api": {
					AllowanceScope: "b",
					FieldAccessRights: []user.FieldAccessDefinition{
						{
							TypeName:  "Query",
							FieldName: "hello",
							Limits: user.FieldLimits{
								MaxQueryDepth: 2,
							},
						},
					},
					Limit: user.APILimit{
						QuotaMax:         int64(2),
						QuotaRenewalRate: int64(2),
						QuotaRenews:      int64(2),
						RateLimit: user.RateLimit{
							Rate: 2.0,
							Per:  2.0,
						},
						ThrottleInterval:   2.0,
						ThrottleRetryLimit: 2.0,
						MaxQueryDepth:      2.0,
					},
				},
			},
		}

		accessDef, allowanceScope, err := GetAccessDefinitionByAPIIDOrSession(sessionWithAPILimits, api)
		assert.Equal(t, &user.AccessDefinition{
			FieldAccessRights: []user.FieldAccessDefinition{
				{
					TypeName:  "Query",
					FieldName: "hello",
					Limits: user.FieldLimits{
						MaxQueryDepth: 2,
					},
				},
			},
			Limit: user.APILimit{
				QuotaMax:         int64(2),
				QuotaRenewalRate: int64(2),
				QuotaRenews:      int64(2),
				RateLimit: user.RateLimit{
					Rate: 2.0,
					Per:  2.0,
				},
				ThrottleInterval:   2.0,
				ThrottleRetryLimit: 2.0,
				MaxQueryDepth:      2.0,
			},
		}, accessDef)
		assert.Equal(t, "b", allowanceScope)
		assert.NoError(t, err)
	})
}

// TestSessionState_RedisStorageSizeReduced verifies that the omitzero optimization
// reduces the size of session data stored in Redis by omitting zero-value fields.
func TestSessionState_RedisStorageSizeReduced(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create an API that requires authentication
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(api)

	// Create a minimal key with only Rate, Per, and one API access right
	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 100
		s.Per = 60
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
			},
		}
		// Explicitly set other fields to zero to test omitzero
		s.QuotaMax = 0
		s.QuotaRenews = 0
		s.QuotaRemaining = 0
		s.QuotaRenewalRate = 0
	})

	// Get the raw JSON value from Redis
	hashKeys := ts.Gw.GetConfig().HashKeys
	hashedKey := storage.HashKey(key, hashKeys)

	redisStore := storage.RedisCluster{
		KeyPrefix:         "apikey-",
		HashKeys:          hashKeys,
		ConnectionHandler: ts.Gw.StorageConnectionHandler,
	}

	// GetRawKey needs the full key including prefix
	fullKey := "apikey-" + hashedKey
	rawJSON, err := redisStore.GetRawKey(fullKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, rawJSON)

	// Log the JSON for debugging
	t.Logf("Session JSON: %s", rawJSON)
	t.Logf("Minimal session JSON size: %d bytes", len(rawJSON))

	// Verify that zero-value fields are omitted (compact JSON)
	// Note: CreateSession sets some fields like last_check, allowance, so we only check
	// fields that are truly zero in our test setup
	assert.NotContains(t, rawJSON, `"hmac_enabled"`, "False hmac_enabled should be omitted")
	assert.NotContains(t, rawJSON, `"is_inactive"`, "False is_inactive should be omitted")
	assert.NotContains(t, rawJSON, `"quota_max"`, "Zero quota_max should be omitted")
	assert.NotContains(t, rawJSON, `"quota_renews"`, "Zero quota_renews should be omitted")
	assert.NotContains(t, rawJSON, `"quota_remaining"`, "Zero quota_remaining should be omitted")
	assert.NotContains(t, rawJSON, `"quota_renewal_rate"`, "Zero quota_renewal_rate should be omitted")
	assert.NotContains(t, rawJSON, `"basic_auth_data"`, "Empty basic_auth_data should be omitted")
	assert.NotContains(t, rawJSON, `"jwt_data"`, "Empty jwt_data should be omitted")
	assert.NotContains(t, rawJSON, `"monitor"`, "Empty monitor should be omitted")
	assert.NotContains(t, rawJSON, `"hmac_string"`, "Empty hmac_string should be omitted")
	assert.NotContains(t, rawJSON, `"certificate"`, "Empty certificate should be omitted")

	// Verify expected fields are present
	assert.Contains(t, rawJSON, `"rate"`)
	assert.Contains(t, rawJSON, `"per"`)
	assert.Contains(t, rawJSON, `"access_rights"`)

	// Verify JSON size is reasonable (should be less than 500 bytes for minimal key)
	assert.Less(t, len(rawJSON), 500, "Minimal session JSON should be under 500 bytes")
}

// TestSessionState_KeyAuthenticationWorksAfterOptimization verifies that authentication
// and rate limiting work correctly with the compact JSON format from omitzero.
func TestSessionState_KeyAuthenticationWorksAfterOptimization(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create an API that requires authentication
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(api)

	// Create a key with rate limiting configured
	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 10 // 10 requests
		s.Per = 60  // per 60 seconds
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
			},
		}
	})

	authHeader := map[string]string{"Authorization": key}

	// Test 1: Authentication works with the compact format
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: authHeader,
		Code:    http.StatusOK,
	})

	// Test 2: Multiple requests work (rate limiting doesn't immediately block)
	for i := 0; i < 5; i++ {
		ts.Run(t, test.TestCase{
			Path:    "/",
			Headers: authHeader,
			Code:    http.StatusOK,
		})
	}

	// Test 3: Invalid key is rejected
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: map[string]string{"Authorization": "invalid-key"},
		Code:    http.StatusForbidden,
	})
}

// TestSessionState_QuotaEnforcementWorksAfterOptimization verifies that quota enforcement
// works correctly with the compact JSON format.
func TestSessionState_QuotaEnforcementWorksAfterOptimization(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create an API that requires authentication
	api := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(api)

	// Create a key with a very small quota (2 requests)
	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 1000        // High rate limit so we hit quota first
		s.Per = 1            // per 1 second
		s.QuotaMax = 2       // Only 2 requests allowed
		s.QuotaRemaining = 2 // 2 remaining
		s.QuotaRenewalRate = 3600
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
			},
		}
	})

	authHeader := map[string]string{"Authorization": key}

	// First 2 requests should succeed
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: authHeader,
		Code:    http.StatusOK,
	})
	ts.Run(t, test.TestCase{
		Path:    "/",
		Headers: authHeader,
		Code:    http.StatusOK,
	})

	// Third request should be quota-limited
	ts.Run(t, test.TestCase{
		Path:      "/",
		Headers:   authHeader,
		Code:      http.StatusForbidden,
		BodyMatch: "Quota exceeded",
	})
}

func TestSessionLimiter_RateLimitInfo(t *testing.T) {
	limiter := &SessionLimiter{config: &config.Default}
	spec := BuildAPI(func(a *APISpec) {
		a.Proxy.ListenPath = "/"
	})[0]

	tests := []struct {
		name      string
		method    string
		path      string
		endpoints user.Endpoints
		expected  *user.EndpointRateLimitInfo
		found     bool
	}{
		{
			name:   "Matching endpoint and method",
			method: http.MethodGet,
			path:   "/api/v1/users",
			endpoints: user.Endpoints{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: &user.EndpointRateLimitInfo{
				KeySuffix: storage.HashStr("GET:/api/v1/users"),
				Rate:      100,
				Per:       60,
			},
			found: true,
		},
		{
			name:   "Matching endpoint, non-matching method",
			path:   "/api/v1/users",
			method: http.MethodPost,
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
		{
			name:   "Non-matching endpoint",
			method: http.MethodGet,
			path:   "/api/v1/products",
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
		{
			name:   "Regex path matching",
			path:   "/api/v1/users/123",
			method: http.MethodGet,
			endpoints: []user.Endpoint{
				{
					Path: "/api/v1/users/[0-9]+",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 50, Per: 30}},
					},
				},
			},
			expected: &user.EndpointRateLimitInfo{
				KeySuffix: storage.HashStr("GET:/api/v1/users/[0-9]+"),
				Rate:      50,
				Per:       30,
			},
			found: true,
		},
		{
			name:   "Invalid regex path",
			path:   "/api/v1/users",
			method: http.MethodGet,
			endpoints: []user.Endpoint{
				{
					Path: "[invalid regex",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: nil,
			found:    false,
		},
		{
			name:   "Invalid regex path and valid url",
			path:   "/api/v1/users",
			method: http.MethodGet,
			endpoints: []user.Endpoint{
				{
					Path: "[invalid regex",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
				{
					Path: "/api/v1/users",
					Methods: []user.EndpointMethod{
						{Name: "GET", Limit: user.RateLimit{Rate: 100, Per: 60}},
					},
				},
			},
			expected: &user.EndpointRateLimitInfo{
				KeySuffix: storage.HashStr("GET:/api/v1/users"),
				Rate:      100,
				Per:       60,
			},
			found: true,
		},
		{
			name:      "nil endpoints",
			path:      "/api/v1/users",
			method:    http.MethodGet,
			endpoints: nil,
			expected:  nil,
			found:     false,
		},
		{
			name:      "empty endpoints",
			path:      "/api/v1/users",
			method:    http.MethodGet,
			endpoints: user.Endpoints{},
			expected:  nil,
			found:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)

			result, found := limiter.RateLimitInfo(req, spec, tt.endpoints)
			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSessionLimiter(t *testing.T) {
	newSessionLimiter := func(t *testing.T) SessionLimiter {
		t.Helper()
		tc := StartTest(nil)
		t.Cleanup(tc.Close)

		cfg := tc.Gw.GetConfig()
		drlManager := &drl.DRL{}
		return NewSessionLimiter(tc.Gw.ctx, &cfg, drlManager, &cfg.ExternalServices)
	}

	limiter := newSessionLimiter(t)
	key := "test"

	t.Run("limitSentinel", func(t *testing.T) {
		t.Run("returns false if key does not exist", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			cmd := limiter.limiterStorage.Del(r.Context(), key+SentinelRateLimitKeyPostfix)
			require.NoError(t, cmd.Err())

			expires, ok := limiter.limitSentinel(
				r,
				&user.SessionState{},
				key,
				&user.APILimit{RateLimit: user.RateLimit{Rate: 60, Per: 60}},
				false,
			)

			require.False(t, ok, "is not blocked if key does not exist")
			require.Equal(t, time.Duration(0), expires, "expires is zero")
		})

		t.Run("returns TTL from the key", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			eps := 0.1
			exp := time.Second * 60
			cmd := limiter.limiterStorage.SetEx(r.Context(), key+SentinelRateLimitKeyPostfix, "1", exp)
			require.NoError(t, cmd.Err())

			expires, ok := limiter.limitSentinel(
				r,
				&user.SessionState{},
				"test",
				&user.APILimit{RateLimit: user.RateLimit{Rate: 60, Per: 60}},
				false,
			)

			require.True(t, ok, "is blocked")
			require.True(t, (expires.Seconds()-exp.Seconds()) < eps, "is in range of epsilon")
		})

		// key without ttl is rather exception, so it has no sens writing tests for this case
	})

	t.Run("extendContextWithQuota", func(t *testing.T) {
		t.Run("extends request with quota information if is enabled", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			limiter.enableContextVariables = true
			limiter.extendContextWithQuota(r, 1, 2, 3)

			data := ctxGetData(r)
			require.NotNil(t, data)
			require.Equal(t, 1, data[ctxDataKeyQuotaLimit])
			require.Equal(t, 2, data[ctxDataKeyQuotaRemaining])
			require.Equal(t, 3, data[ctxDataKeyQuotaReset])
		})

		t.Run("does not extend request with quota information if is disabled", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			limiter.enableContextVariables = false
			limiter.extendContextWithQuota(r, 1, 2, 3)

			data := ctxGetData(r)
			require.Nil(t, data)
		})
	})

	t.Run("extendContextWithLimits", func(t *testing.T) {
		t.Run("extends", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			limiter.enableContextVariables = true
			limiter.extendContextWithLimits(r, rate.Stats{
				Limit:     2,
				Remaining: 1,
				Reset:     time.Second * 10,
			})

			data := ctxGetData(r)
			require.NotNil(t, data)
			assert.Equal(t, 2, data[ctxDataKeyRateLimitLimit])
			assert.Equal(t, 1, data[ctxDataKeyRateLimitRemaining])
			assert.Equal(t, 10, data[ctxDataKeyRateLimitReset])
		})

		t.Run("does not extend if is disabled", func(t *testing.T) {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			require.NoError(t, err)

			limiter.enableContextVariables = false
			limiter.extendContextWithLimits(r, rate.Stats{})

			data := ctxGetData(r)
			require.Nil(t, data)
		})
	})

	t.Run("limitRedis", func(t *testing.T) {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		require.NoError(t, err)

		cmd := limiter.limiterStorage.Del(r.Context(), key+SentinelRateLimitKeyPostfix, key)
		require.NoError(t, cmd.Err())

		session := &user.SessionState{}
		apiLimit := &user.APILimit{RateLimit: user.RateLimit{Rate: 2, Per: 60}}

		state, block := limiter.limitRedis(r, session, key, apiLimit, false)
		assert.True(t, state.Reset == 0, "first cal is not blocked reset")
		assert.False(t, block, "first cal is not blocked block")

		state, block = limiter.limitRedis(r, session, key, apiLimit, false)
		assert.InDelta(t, 60.0, state.Reset.Seconds(), 0.1, "second cal is blocked for all")
		assert.False(t, block, "second cal is not blocked block")

		state, block = limiter.limitRedis(r, session, key, apiLimit, false)
		assert.InDelta(t, 60.0, state.Reset.Seconds(), 0.1, "third call is blocked for all window size")
		assert.True(t, block, "third call is blocked")
	})
}
