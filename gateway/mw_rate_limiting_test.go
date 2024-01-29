package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

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
	g := StartTest(nil)
	defer g.Close()

	spec := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})[0]

	sessionWithQuotaSettings, keyWithQuotaSettings := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					QuotaRenewalRate: 0,
					QuotaMax:         1,
				},
			},
		}
		s.MetaData = map[string]interface{}{
			"quota_pattern": "$tyk_meta.developer_id",
			"developer_id":  "portal-app-1",
		}
	})

	_, keyWithExceededQuotaSettings := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					QuotaRenewalRate: 0,
					QuotaMax:         1,
				},
			},
		}
		s.MetaData = map[string]interface{}{
			"quota_pattern": "$tyk_meta.developer_id",
			"developer_id":  "portal-app-2",
		}
	})

	sessionWithRatelimitSettings, keyWithRatelimitSettings := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					Rate: 1,
					Per:  1000,
				},
			},
		}
		s.MetaData = map[string]interface{}{
			"rate_limit_pattern": "$tyk_meta.developer_id",
			"developer_id":       "portal-app-1",
		}
	})

	_, keyWithExceededRatelimitSettings := g.CreateSession(func(s *user.SessionState) {
		s.MaxQueryDepth = -1
		s.AccessRights = map[string]user.AccessDefinition{
			spec.APIID: {
				APIID:   spec.APIID,
				APIName: spec.Name,
				Limit: user.APILimit{
					Rate: 1,
					Per:  1000,
				},
			},
		}
		s.MetaData = map[string]interface{}{
			"rate_limit_pattern": "$tyk_meta.developer_id",
			"developer_id":       "portal-app-2",
		}
	})

	authHeaderWithQuotaSettings := map[string]string{header.Authorization: keyWithQuotaSettings}
	authHeaderWithExceededQuotaSettings := map[string]string{header.Authorization: keyWithExceededQuotaSettings}
	authHeaderWithRatelimitSettings := map[string]string{header.Authorization: keyWithRatelimitSettings}
	authHeaderWithExceededRatelimitSettings := map[string]string{header.Authorization: keyWithExceededRatelimitSettings}

	t.Run("Custom quota key", func(t *testing.T) {

		// Reach quota.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithQuotaSettings, Code: http.StatusOK},
			{Headers: authHeaderWithQuotaSettings, Code: http.StatusForbidden},
		}...)

		// Update the custom quota key, the gateway should pick up the new custom key.
		sessionWithQuotaSettings.MetaData["developer_id"] = "portal-app-2"
		_ = g.Gw.GlobalSessionManager.UpdateSession(keyWithQuotaSettings, sessionWithQuotaSettings, 0, false)

		// The first call should go through because now the quota is calculated against the new quota key.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithQuotaSettings, Code: http.StatusOK},
			{Headers: authHeaderWithQuotaSettings, Code: http.StatusForbidden},
		}...)

		// Now trying to call the same API with the same quota key as in the previous example but from different session.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithExceededQuotaSettings, Code: http.StatusForbidden},
		}...)
	})

	t.Run("Custom ratelimit key", func(t *testing.T) {

		// Reach quota.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithRatelimitSettings, Code: http.StatusOK},
			{Headers: authHeaderWithRatelimitSettings, Code: http.StatusTooManyRequests},
		}...)

		// Update the custom quota key, the gateway should pick up the new custom key.
		sessionWithRatelimitSettings.MetaData["developer_id"] = "portal-app-2"
		_ = g.Gw.GlobalSessionManager.UpdateSession(keyWithRatelimitSettings, sessionWithRatelimitSettings, 0, false)

		// The first call should go through because now the quota is calculated against the new quota key.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithRatelimitSettings, Code: http.StatusOK},
			{Headers: authHeaderWithRatelimitSettings, Code: http.StatusTooManyRequests},
		}...)

		// Now trying to call the same API with the same ratelimit key as in the previous example but from different session.
		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeaderWithExceededRatelimitSettings, Code: http.StatusTooManyRequests},
		}...)
	})
}
