package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestRateLimit_Unlimited(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
	})[0]

	session, key := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIName: api.Name,
				APIID:   api.APIID,
			},
		}
		s.Rate = 1
		s.Per = 60
	})

	authHeader := map[string]string{
		header.Authorization: key,
	}

	_, _ = g.Run(t, []test.TestCase{
		{Headers: authHeader, Code: http.StatusOK},
		{Headers: authHeader, Code: http.StatusTooManyRequests},
	}...)

	t.Run("-1 rate means unlimited", func(t *testing.T) {
		session.Rate = -1

		_ = g.Gw.GlobalSessionManager.UpdateSession(key, session, 60, false)

		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeader, Code: http.StatusOK},
			{Headers: authHeader, Code: http.StatusOK},
		}...)
	})

	t.Run("0 rate means unlimited", func(t *testing.T) {
		session.Rate = 0

		_ = g.Gw.GlobalSessionManager.UpdateSession(key, session, 60, false)

		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeader, Code: http.StatusOK},
			{Headers: authHeader, Code: http.StatusOK},
		}...)
	})
}

func TestNeverRenewQuota(t *testing.T) {

	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "api to test quota never renews"
		spec.APIID = "api to test quota never renews"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
	})[0]

	_, key := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIName: api.Name,
				APIID:   api.APIID,
				Limit: user.APILimit{
					QuotaRenewalRate: 0,
					QuotaMax:         1,
				},
			},
		}
	})

	authHeader := map[string]string{
		header.Authorization: key,
	}

	_, _ = g.Run(t, []test.TestCase{
		{Headers: authHeader, Code: http.StatusOK},
		{Headers: authHeader, Code: http.StatusForbidden},
	}...)

}

func TestMwRateLimiting_DepthLimit(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	spec := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
		spec.GraphQL.Enabled = true
	})[0]

	sessionWithGlobalDepthLimit, keyWithGlobalDepthLimit := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
			},
		}
	})

	sessionWithAPILevelDepthLimit, keyWithAPILevelDepthLimit := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					MaxQueryDepth: 1,
				},
			},
		}
	})

	sessionWithFieldLevelDepthLimit, keyWithFieldLevelDepthLimit := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					MaxQueryDepth: -1,
				},
				FieldAccessRights: []user.FieldAccessDefinition{
					{TypeName: "Query", FieldName: "people", Limits: user.FieldLimits{MaxQueryDepth: 1}},
				},
			},
		}
	})

	authHeader := map[string]string{header.Authorization: keyWithGlobalDepthLimit}
	authHeaderWithAPILevelDepthLimit := map[string]string{header.Authorization: keyWithAPILevelDepthLimit}
	authHeaderWithFieldLevelDepthLimit := map[string]string{header.Authorization: keyWithFieldLevelDepthLimit}

	request := graphql.Request{
		OperationName: "Query",
		Variables:     nil,
		Query:         "query Query { people { name country { name } } }",
	}

	t.Run("Global Level", func(t *testing.T) {
		assert.Equal(t, -1, sessionWithGlobalDepthLimit.MaxQueryDepth)

		// Global depth will be used.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeader, Data: request, Code: http.StatusOK},
		}...)
	})

	t.Run("API Level", func(t *testing.T) {
		assert.Equal(t, -1, sessionWithAPILevelDepthLimit.MaxQueryDepth)
		assert.Equal(t, 1, sessionWithAPILevelDepthLimit.AccessRights[spec.APIID].Limit.MaxQueryDepth)

		// Although global is unlimited, it will be ignored because api level depth value is set.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithAPILevelDepthLimit, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
		}...)
	})

	t.Run("Field Level", func(t *testing.T) {
		assert.Equal(t, -1, sessionWithFieldLevelDepthLimit.MaxQueryDepth)
		assert.Equal(t, -1, sessionWithFieldLevelDepthLimit.AccessRights[spec.APIID].Limit.MaxQueryDepth)
		assert.Equal(t, 1, sessionWithFieldLevelDepthLimit.AccessRights[spec.APIID].FieldAccessRights[0].Limits.MaxQueryDepth)

		// Although global and api level depths are unlimited, it will be ignored because field level depth value is set.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithFieldLevelDepthLimit, Data: request, BodyMatch: "depth limit exceeded", Code: http.StatusForbidden},
		}...)
	})
}

func TestMwRateLimiting_CustomRatelimitKey(t *testing.T) {
	tcs := []struct {
		name     string
		hashKey  bool
		hashAlgo string
	}{
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

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := StartTest(func(globalConf *config.Config) {
				globalConf.HashKeys = tc.hashKey
				globalConf.HashKeyFunction = tc.hashAlgo
			})
			defer g.Close()

			ok := g.Gw.GlobalSessionManager.Store().DeleteAllKeys()
			assert.True(t, ok)

			customRateLimitKey := "portal-developer-1" + tc.hashAlgo

			spec := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.UseKeylessAccess = false
				spec.Proxy.ListenPath = "/"
			})[0]

			_, firstQuotaKey := g.CreateSession(func(s *user.SessionState) {
				s.MaxQueryDepth = -1
				s.AccessRights = map[string]user.AccessDefinition{
					spec.APIID: {
						APIID:   spec.APIID,
						APIName: spec.Name,
						Limit: user.APILimit{
							QuotaRenewalRate: 0,
							QuotaMax:         3,
						},
					},
				}
				s.MetaData = map[string]interface{}{
					"rate_limit_pattern": "$tyk_meta.developer_id",
					"developer_id":       customRateLimitKey,
				}
			})

			_, secondQuotaKey := g.CreateSession(func(s *user.SessionState) {
				s.MaxQueryDepth = -1
				s.AccessRights = map[string]user.AccessDefinition{
					spec.APIID: {
						APIID:   spec.APIID,
						APIName: spec.Name,
						Limit: user.APILimit{
							QuotaRenewalRate: 0,
							QuotaMax:         3,
						},
					},
				}
				s.MetaData = map[string]interface{}{
					"rate_limit_pattern": "$tyk_meta.developer_id",
					"developer_id":       customRateLimitKey,
				}
			})

			_, firstRLKey := g.CreateSession(func(s *user.SessionState) {
				s.MaxQueryDepth = -1
				s.AccessRights = map[string]user.AccessDefinition{
					spec.APIID: {
						APIID:   spec.APIID,
						APIName: spec.Name,
						Limit: user.APILimit{
							Rate: 3,
							Per:  1000,
						},
					},
				}
				s.MetaData = map[string]interface{}{
					"rate_limit_pattern": "$tyk_meta.developer_id",
					"developer_id":       customRateLimitKey,
				}
			})

			_, secondRLKey := g.CreateSession(func(s *user.SessionState) {
				s.MaxQueryDepth = -1
				s.AccessRights = map[string]user.AccessDefinition{
					spec.APIID: {
						APIID:   spec.APIID,
						APIName: spec.Name,
						Limit: user.APILimit{
							Rate: 3,
							Per:  1000,
						},
					},
				}
				s.MetaData = map[string]interface{}{
					"rate_limit_pattern": "$tyk_meta.developer_id",
					"developer_id":       customRateLimitKey,
				}
			})

			authHeaderFirstQuotaKey := map[string]string{header.Authorization: firstQuotaKey}
			authHeaderSecondQuotaKey := map[string]string{header.Authorization: secondQuotaKey}
			authHeaderFirstRLKey := map[string]string{header.Authorization: firstRLKey}
			authHeaderSecondRLKey := map[string]string{header.Authorization: secondRLKey}

			t.Run("Custom quota key", func(t *testing.T) {

				// Make first two calls with the first key. Both calls should be 200 OK since the quota is 3 calls.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderFirstQuotaKey, Code: http.StatusOK},
					{Headers: authHeaderFirstQuotaKey, Code: http.StatusOK},
				}...)

				// The first call with the second key should be 200 OK.
				// The next call should be 403 since the quota of 3 calls is shared between two credentials.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderSecondQuotaKey, Code: http.StatusOK},
					{Headers: authHeaderSecondQuotaKey, Code: http.StatusForbidden},
				}...)

				// Since both keys have the same ratelimit key, the quota for the first key should be already spent.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderFirstQuotaKey, Code: http.StatusForbidden},
				}...)
			})

			t.Run("Custom ratelimit key", func(t *testing.T) {

				// Make first two calls with the first key. Both calls should be 200 OK since the RL is 3 calls / 1000 s.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderFirstRLKey, Code: http.StatusOK},
					{Headers: authHeaderFirstRLKey, Code: http.StatusOK},
				}...)

				// The first call with the second key should be 200 OK.
				// The next call should be 429 since the ratelimit of 3 calls / 1000 s is shared between two credentials.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderSecondRLKey, Code: http.StatusOK},
					{Headers: authHeaderSecondRLKey, Code: http.StatusTooManyRequests},
				}...)

				// Since both keys have the same ratelimit key, the raltelimit for the first key should be already spent.
				_, _ = g.Run(t, []test.TestCase{
					{Headers: authHeaderFirstRLKey, Code: http.StatusTooManyRequests},
				}...)
			})

		})
	}
}
