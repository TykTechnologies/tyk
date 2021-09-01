package gateway

import (
	"net/http"
	"testing"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestRateLimit_Unlimited(t *testing.T) {
	g := StartTest()
	defer g.Close()

	DRLManager.SetCurrentTokenValue(1)
	DRLManager.RequestTokenValue = 1

	api := BuildAndLoadAPI(func(spec *APISpec) {
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
		headers.Authorization: key,
	}

	_, _ = g.Run(t, []test.TestCase{
		{Headers: authHeader, Code: http.StatusOK},
		{Headers: authHeader, Code: http.StatusTooManyRequests},
	}...)

	t.Run("-1 rate means unlimited", func(t *testing.T) {
		session.Rate = -1

		_ = GlobalSessionManager.UpdateSession(key, session, 60, false)

		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeader, Code: http.StatusOK},
			{Headers: authHeader, Code: http.StatusOK},
		}...)
	})

	t.Run("0 rate means unlimited", func(t *testing.T) {
		session.Rate = 0

		_ = GlobalSessionManager.UpdateSession(key, session, 60, false)

		_, _ = g.Run(t, []test.TestCase{
			{Headers: authHeader, Code: http.StatusOK},
			{Headers: authHeader, Code: http.StatusOK},
		}...)
	})

	DRLManager.SetCurrentTokenValue(0)
	DRLManager.RequestTokenValue = 0
}

func TestNeverRenewQuota(t *testing.T) {

	g := StartTest()
	defer g.Close()

	api := BuildAndLoadAPI(func(spec *APISpec) {
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
		headers.Authorization: key,
	}

	_, _ = g.Run(t, []test.TestCase{
		{Headers: authHeader, Code: http.StatusOK},
		{Headers: authHeader, Code: http.StatusForbidden},
	}...)

}

func TestMwRateLimiting_DepthLimit(t *testing.T) {
	g := StartTest()
	defer g.Close()

	spec := BuildAndLoadAPI(func(spec *APISpec) {
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

	authHeader := map[string]string{headers.Authorization: keyWithGlobalDepthLimit}
	authHeaderWithAPILevelDepthLimit := map[string]string{headers.Authorization: keyWithAPILevelDepthLimit}
	authHeaderWithFieldLevelDepthLimit := map[string]string{headers.Authorization: keyWithFieldLevelDepthLimit}

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
