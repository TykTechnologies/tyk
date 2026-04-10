package rate_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func rlTestRunnerProvider(t *testing.T, hashKey bool, hashAlgo string, limiter string) *Test {
	t.Helper()
	ts := StartTest(nil)

	globalConf := ts.Gw.GetConfig()

	globalConf.HashKeys = hashKey
	globalConf.HashKeyFunction = hashAlgo

	switch limiter {
	case "Redis":
		globalConf.RateLimit.EnableRedisRollingLimiter = true
	case "Sentinel":
		globalConf.RateLimit.EnableSentinelRateLimiter = true
	case "DRL":
		globalConf.RateLimit.DRLEnableSentinelRateLimiter = true
	case "NonTransactional":
		globalConf.RateLimit.EnableNonTransactionalRateLimiter = true
	case "FixedWindow":
		globalConf.RateLimit.EnableFixedWindowRateLimiter = true
	default:
		t.Fatal("There is no such a rate limiter:", limiter)
	}

	ts.Gw.SetConfig(globalConf)

	ok := ts.Gw.GlobalSessionManager.Store().DeleteAllKeys()
	assert.True(t, ok)

	return ts
}

func endpointRateLimitTestHelper(t *testing.T, limiter string, beforeFn func()) {
	t.Helper()
	type rlTestCase struct {
		name     string
		hashKey  bool
		hashAlgo string
	}

	var rlTestCases = []rlTestCase{
		{
			name:    "hash_key false",
			hashKey: false,
		},
		{
			name:     "hash_key true murmur64",
			hashKey:  true,
			hashAlgo: "murmur64",
		},
		{
			name:     "hash_key true murmur32",
			hashKey:  true,
			hashAlgo: "murmur32",
		},
		{
			name:     "hash_key true sha256",
			hashKey:  true,
			hashAlgo: "sha256",
		},
	}

	for _, tc := range rlTestCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ts := rlTestRunnerProvider(t, tc.hashKey, tc.hashAlgo, limiter)
			defer ts.Close()
			apis := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.Proxy.ListenPath = "/api-1"
			}, func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.Proxy.ListenPath = "/api-2"
			}, func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.Proxy.ListenPath = "/api-3"
			})

			api1, api2, api3 := apis[0], apis[1], apis[2]

			_, endpointRLKey := ts.CreateSession(func(s *user.SessionState) {
				s.Rate = 2
				s.Per = 1000
				s.AccessRights = map[string]user.AccessDefinition{
					api1.APIID: {
						APIID:   api1.APIID,
						APIName: api1.Name,
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 3,
								Per:  1000,
							},
						},
						Endpoints: []user.Endpoint{
							{
								Path: "/get",
								Methods: []user.EndpointMethod{
									{
										Name: http.MethodGet,
										Limit: user.RateLimit{
											Rate: 5,
											Per:  1000,
										},
									},
								},
							},
							{
								Path: "/post",
								Methods: []user.EndpointMethod{
									{
										Name: http.MethodPost,
										Limit: user.RateLimit{
											Rate: 4,
											Per:  1000,
										},
									},
								},
							},
						},
					},
					api2.APIID: {
						APIID:   api2.APIID,
						APIName: api2.Name,
						Limit: user.APILimit{
							RateLimit: user.RateLimit{
								Rate: 3,
								Per:  1000,
							},
						},
					},
					api3.APIID: {
						APIID:   api3.APIID,
						APIName: api3.Name,
					},
				}
			})

			authHeaders := map[string]string{header.Authorization: endpointRLKey}

			_, _ = ts.Run(t, []test.TestCase{
				// first 3 calls should pass through for an endpoint that is not specified for api-1.
				{Headers: authHeaders, Path: "/api-1", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1", Code: http.StatusOK},

				{BeforeFn: beforeFn, Headers: authHeaders, Path: "/api-1", Code: http.StatusTooManyRequests},

				// GET /get endpoint should have separate RL counter for api-1.
				{Headers: authHeaders, Path: "/api-1/get", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1/get", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1/get", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1/get", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-1/get", Code: http.StatusOK},

				{BeforeFn: beforeFn, Headers: authHeaders, Path: "/api-1/get", Code: http.StatusTooManyRequests},

				// POST /post endpoint should have separate RL for api-1.
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-1/post", Code: http.StatusOK},
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-1/post", Code: http.StatusOK},
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-1/post", Code: http.StatusOK},
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-1/post", Code: http.StatusOK},

				{BeforeFn: beforeFn, Headers: authHeaders, Method: http.MethodPost, Path: "/api-1/post", Code: http.StatusTooManyRequests},

				// GET /status/200 should use API level rate limit of api-1.
				{Headers: authHeaders, Path: "/api-1/status/200", Code: http.StatusTooManyRequests},

				// all endpoints should be using API level rate limit for api-2.
				{Headers: authHeaders, Path: "/api-2/get", Code: http.StatusOK},
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-2/post", Code: http.StatusOK},
				{Headers: authHeaders, Path: "/api-2/status/200", Code: http.StatusOK},

				{BeforeFn: beforeFn, Headers: authHeaders, Path: "/api-1/status/200", Code: http.StatusTooManyRequests},

				// api-3 should be using global rate limit.
				{Headers: authHeaders, Path: "/api-3/get", Code: http.StatusOK},
				{Headers: authHeaders, Method: http.MethodPost, Path: "/api-3/post", Code: http.StatusOK},
				{BeforeFn: beforeFn, Headers: authHeaders, Path: "/api-3/status/200", Code: http.StatusTooManyRequests},
			}...)
		})
	}
}

func TestEndpointRL_NonTransactional(t *testing.T) {
	endpointRateLimitTestHelper(t, "NonTransactional", nil)
}

func TestEndpointRL_Redis(t *testing.T) {
	endpointRateLimitTestHelper(t, "Redis", nil)
}

func TestEndpointRL_Sentinel(t *testing.T) {
	// add a small delay before expecting rate limit exceeded in sentinel rate limiter.
	endpointRateLimitTestHelper(t, "Sentinel", func() {
		time.Sleep(time.Millisecond * 5)
	})
}

func TestEndpointRL_DRL(t *testing.T) {
	endpointRateLimitTestHelper(t, "DRL", nil)
}

func TestEndpointRL_FixedWindow(t *testing.T) {
	endpointRateLimitTestHelper(t, "FixedWindow", nil)
}
