package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestGranularAccessMiddleware_ProcessRequest(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
	})[0]

	_, directKey := g.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedURLs: []user.AccessSpec{
					{
						URL:     "^/valid_path.*",
						Methods: []string{"GET"},
					},
				},
			},
		}
	})

	pID := g.CreatePolicy(func(p *user.Policy) {
		p.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIID:   api.APIID,
				APIName: api.Name,
				AllowedURLs: []user.AccessSpec{
					{
						URL:     "^/valid_path.*",
						Methods: []string{"GET"},
					},
				},
			},
		}
	})

	_, policyAppliedKey := g.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{pID}
	})

	t.Run("Direct key", func(t *testing.T) {
		authHeaderWithDirectKey := map[string]string{
			header.Authorization: directKey,
		}

		t.Run("should return 200 OK on allowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on allowed path with disallowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/valid_path",
					Method:  http.MethodPost,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on disallowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/invalid_path",
					Method:  http.MethodGet,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithDirectKey,
				},
			}...)
		})

	})

	t.Run("Policy applied key", func(t *testing.T) {
		authHeaderWithPolicyAppliedKey := map[string]string{
			header.Authorization: policyAppliedKey,
		}

		t.Run("should return 200 OK on allowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/valid_path",
					Method:  http.MethodGet,
					Code:    http.StatusOK,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on allowed path with disallowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/valid_path",
					Method:  http.MethodPost,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})

		t.Run("should return 403 Forbidden on disallowed path with allowed method", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:    "/invalid_path",
					Method:  http.MethodGet,
					Code:    http.StatusForbidden,
					Headers: authHeaderWithPolicyAppliedKey,
				},
			}...)
		})
	})
}
