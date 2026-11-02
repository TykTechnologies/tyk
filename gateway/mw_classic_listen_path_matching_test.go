package gateway

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// loadEmployeesClassicAPI loads a Tyk Classic API whose listen path is a text
// prefix of its own endpoint paths, as reported in TT-18822.
func loadEmployeesClassicAPI(ts *Test, versionGen func(v *apidef.VersionInfo)) *APISpec {
	return ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/employees"
		spec.Proxy.StripListenPath = true
		spec.UseKeylessAccess = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			versionGen(v)
		})
	})[0]
}

func employeesAllowList(v *apidef.VersionInfo) {
	v.ExtendedPaths.WhiteList = []apidef.EndPointMeta{
		{Path: "/employees/static", Method: http.MethodGet},
		{Path: "/employees/{id}", Method: http.MethodGet},
	}
}

func TestClassicAllowList_ListenPathPrefixOfEndpoints(t *testing.T) {
	t.Run("endpoints match only the path proxied upstream", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		loadEmployeesClassicAPI(ts, employeesAllowList)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/employees/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/123"`},
			{Path: "/employees/static", Code: http.StatusForbidden},
			{Path: "/employees/qzxjklmwvbnpfgh", Code: http.StatusForbidden},
			{Path: "/employees/foo/bar", Code: http.StatusForbidden},
		}...)
	})

	t.Run("exact path matching rejects extra segments for parameterised endpoints", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.HttpServerOptions.EnablePathPrefixMatching = true
			globalConf.HttpServerOptions.EnablePathSuffixMatching = true
		})
		defer ts.Close()

		loadEmployeesClassicAPI(ts, employeesAllowList)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/123"`},
			{Path: "/employees/employees/123/extra", Code: http.StatusForbidden},
			{Path: "/employees/static", Code: http.StatusForbidden},
			{Path: "/employees/qzxjklmwvbnpfgh", Code: http.StatusForbidden},
		}...)
	})

	t.Run("allow_unsafe_listen_path_matching restores the full URL fallback", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AllowUnsafeListenPathMatching = true
		})
		defer ts.Close()

		loadEmployeesClassicAPI(ts, employeesAllowList)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
			{Path: "/employees/hello_world", Code: http.StatusOK, BodyMatch: `"Url":"/hello_world"`},
			{Path: "/employees/foo/bar", Code: http.StatusOK, BodyMatch: `"Url":"/foo/bar"`},
		}...)
	})
}

// TestClassicAllowList_ListenPathNotStripped checks that an endpoint declared
// with the listen path still matches when the listen path is not stripped, as
// the full request path is then the path proxied upstream.
func TestClassicAllowList_ListenPathNotStripped(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/employees"
		spec.Proxy.StripListenPath = false
		spec.UseKeylessAccess = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			employeesAllowList(v)
		})
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
		{Path: "/employees/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/123"`},
	}...)
}

// TestClassicBlockList_ListenPathPrefixOfEndpoints checks that dropping the
// full URL fallback does not let requests through a block list: a block list
// entry that includes the listen path keeps blocking the full request path.
func TestClassicBlockList_ListenPathPrefixOfEndpoints(t *testing.T) {
	for _, allowUnsafe := range []bool{false, true} {
		t.Run("allow_unsafe_listen_path_matching="+strconv.FormatBool(allowUnsafe), func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.AllowUnsafeListenPathMatching = allowUnsafe
			})
			defer ts.Close()

			loadEmployeesClassicAPI(ts, func(v *apidef.VersionInfo) {
				v.ExtendedPaths.BlackList = []apidef.EndPointMeta{
					{Path: "/employees/admin", Method: http.MethodGet},
				}
			})

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/employees/admin", Code: http.StatusForbidden},
				{Path: "/employees/employees/admin", Code: http.StatusForbidden},
				{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
			}...)
		})
	}
}

// TestClassicEndpointMiddleware_ListenPathPrefixOfEndpoints covers endpoint-level
// middleware matched through getMatchPathAndMethod, which used to strip the
// listen path a second time. The full URL fallback masked that for endpoints
// that include the listen path.
func TestClassicEndpointMiddleware_ListenPathPrefixOfEndpoints(t *testing.T) {
	transformHeader := func(v *apidef.VersionInfo) {
		v.ExtendedPaths.TransformHeader = []apidef.HeaderInjectionMeta{{
			Path:       "/employees/static",
			Method:     http.MethodGet,
			AddHeaders: map[string]string{"X-Matched": "yes"},
		}}
	}

	t.Run("middleware applies to the endpoint proxied upstream", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		loadEmployeesClassicAPI(ts, transformHeader)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"X-Matched":"yes"`},
			{Path: "/employees/static", Code: http.StatusOK, BodyNotMatch: `X-Matched`},
		}...)
	})

	t.Run("allow_unsafe_listen_path_matching keeps the legacy matching", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AllowUnsafeListenPathMatching = true
		})
		defer ts.Close()

		loadEmployeesClassicAPI(ts, transformHeader)

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"X-Matched":"yes"`},
		}...)
	})
}

// TestGranularAccess_ListenPathPrefixOfAllowedURLs covers per-key path based
// permissions (allowed_urls) on a Tyk Classic API.
func TestGranularAccess_ListenPathPrefixOfAllowedURLs(t *testing.T) {
	setup := func(t *testing.T, conf func(*config.Config), allowedURL string) (*Test, map[string]string) {
		t.Helper()

		ts := StartTest(conf)
		t.Cleanup(ts.Close)

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/employees"
			spec.Proxy.StripListenPath = true
			spec.UseKeylessAccess = false
		})[0]

		_, key := ts.CreateSession(func(s *user.SessionState) {
			s.AccessRights = map[string]user.AccessDefinition{
				api.APIID: {
					APIID:       api.APIID,
					APIName:     api.Name,
					AllowedURLs: []user.AccessSpec{{URL: allowedURL, Methods: []string{http.MethodGet}}},
				},
			}
		})

		return ts, map[string]string{header.Authorization: key}
	}

	t.Run("prefix matching matches only the path proxied upstream", func(t *testing.T) {
		ts, headers := setup(t, func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = true
		}, "^/employees/static")

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Headers: headers, Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/static", Headers: headers, Code: http.StatusForbidden},
		}...)
	})

	t.Run("prefix matching with allow_unsafe_listen_path_matching also matches the full request path", func(t *testing.T) {
		ts, headers := setup(t, func(c *config.Config) {
			c.HttpServerOptions.EnablePathPrefixMatching = true
			c.AllowUnsafeListenPathMatching = true
		}, "^/employees/static")

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Headers: headers, Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/static", Headers: headers, Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
		}...)
	})

	t.Run("wildcard matching keeps matching the full request path", func(t *testing.T) {
		ts, headers := setup(t, nil, "/employees/static$")

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/static", Headers: headers, Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
			{Path: "/employees/other", Headers: headers, Code: http.StatusForbidden},
		}...)
	})
}
