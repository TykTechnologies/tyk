package gateway

import (
	"net/http"
	"testing"

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
