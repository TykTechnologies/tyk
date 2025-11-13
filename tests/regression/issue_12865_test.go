package regression

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func Test_Issue12865(t *testing.T) {
	t.Run("Wildcard", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = false
			c.HttpServerOptions.EnablePathSuffixMatching = false
		})
		t.Cleanup(ts.Close)

		// load api definition from file
		api := LoadAPISpec(t, "testdata/issue-12865.json")

		ts.Gw.LoadAPI(api)

		_, directKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
					Limit: user.APILimit{
						QuotaMax: 30,
					},
				},
			}
		})

		headers := map[string]string{
			header.Authorization: directKey,
		}

		// issue request against /test to trigger panic
		ts.Run(t, []test.TestCase{
			{Path: "/test/anything", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/health", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Headers: headers, Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200/anything", Method: http.MethodGet, Code: http.StatusOK},
		}...)
	})

	t.Run("Prefix", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = true
			c.HttpServerOptions.EnablePathSuffixMatching = false
		})
		t.Cleanup(ts.Close)

		// load api definition from file
		api := LoadAPISpec(t, "testdata/issue-12865.json")

		ts.Gw.LoadAPI(api)

		_, directKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
					Limit: user.APILimit{
						QuotaMax: 30,
					},
				},
			}
		})

		headers := map[string]string{
			header.Authorization: directKey,
		}

		// issue request against /test to trigger panic
		ts.Run(t, []test.TestCase{
			{Path: "/test/anything", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/health", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Headers: headers, Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200/anything", Method: http.MethodGet, Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("Prefix and Suffix", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = true
			c.HttpServerOptions.EnablePathSuffixMatching = true
		})
		t.Cleanup(ts.Close)

		// load api definition from file
		api := LoadAPISpec(t, "testdata/issue-12865.json")

		ts.Gw.LoadAPI(api)

		_, directKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
					Limit: user.APILimit{
						QuotaMax: 30,
					},
				},
			}
		})

		headers := map[string]string{
			header.Authorization: directKey,
		}

		// issue request against /test to trigger panic
		ts.Run(t, []test.TestCase{
			{Path: "/test/anything", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/health", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Path: "/test/anything/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Headers: headers, Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200/anything", Method: http.MethodGet, Code: http.StatusUnauthorized},
		}...)
	})

	t.Run("Suffix", func(t *testing.T) {
		ts := gateway.StartTest(func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = false
			c.HttpServerOptions.EnablePathSuffixMatching = true
		})
		t.Cleanup(ts.Close)

		// load api definition from file
		api := LoadAPISpec(t, "testdata/issue-12865.json")

		ts.Gw.LoadAPI(api)

		_, directKey := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:   api.APIID,
					APIName: api.Name,
					Limit: user.APILimit{
						QuotaMax: 30,
					},
				},
			}
		})

		headers := map[string]string{
			header.Authorization: directKey,
		}

		// issue request against /test to trigger panic
		ts.Run(t, []test.TestCase{
			{Path: "/test/anything", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/anything/health", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Path: "/test/anything/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusUnauthorized},
			{Headers: headers, Path: "/test/status/200", Method: http.MethodGet, Code: http.StatusOK},
			{Path: "/test/status/200/anything", Method: http.MethodGet, Code: http.StatusNotFound},
		}...)
	})

}
