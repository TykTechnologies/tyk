package gateway

import (
	"fmt"
	"net/http"
	_ "path"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/stretchr/testify/assert"
)

func TestOpenTracing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	trace.SetupTracing("test", nil)
	defer trace.Close()

	t.Run("ensure the manager is enabled", func(ts *testing.T) {

		if !trace.IsEnabled() {
			ts.Error("expected tracing manager should be enabled")
		}
	})

	t.Run("ensure services are initialized", func(tst *testing.T) {
		var s atomic.Value
		trace.SetInit(func(name string, service string, opts map[string]interface{}, logger trace.Logger) (trace.Tracer, error) {
			s.Store(service)
			return trace.NoopTracer{}, nil
		})
		name := "trace"
		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Name = name
				spec.UseOauth2 = true
			},
		)
		var n string
		if v := s.Load(); v != nil {
			n = v.(string)
		}
		if name != n {
			tst.Errorf("expected %s got %s", name, n)
		}
	})
}

func TestInternalAPIUsage(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	internal := BuildAPI(func(spec *APISpec) {
		spec.Name = "internal"
		spec.APIID = "test1"
		spec.Proxy.ListenPath = "/"
	})[0]

	normal := BuildAPI(func(spec *APISpec) {
		spec.Name = "normal"
		spec.APIID = "test2"
		spec.Proxy.TargetURL = fmt.Sprintf("tyk://%s", internal.Name)
		spec.Proxy.ListenPath = "/normal-api"
	})[0]

	g.Gw.LoadAPI(internal, normal)

	t.Run("with name", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})

	t.Run("with api id", func(t *testing.T) {
		normal.Proxy.TargetURL = fmt.Sprintf("tyk://%s", internal.APIID)

		g.Gw.LoadAPI(internal, normal)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})
}

func TestFuzzyFindAPI(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "IgnoreCase"
		spec.APIID = "123456"
		spec.Proxy.ListenPath = "/"
	})

	spec := ts.Gw.fuzzyFindAPI("ignoreCase")
	assert.Equal(t, "123456", spec.APIID)
}

/*
func TestGraphQLPlayground(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const apiName = "graphql-api"

	api := BuildAPI(func(spec *APISpec) {
		spec.APIID = "APIID"
		spec.Proxy.ListenPath = fmt.Sprintf("/%s/", apiName)
		spec.GraphQL.Enabled = true
		spec.GraphQL.GraphQLPlayground.Enabled = true
	})[0]

	run := func(t *testing.T, playgroundPath string, api *APISpec, env string) {
		endpoint := api.Proxy.ListenPath
		if env == "cloud" {
			endpoint = fmt.Sprintf("/%s/", api.Slug)
		}

		t.Run("playground html is loaded", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: playgroundPath, BodyMatch: `<title>API Playground</title>`, Code: http.StatusOK},
				{Path: playgroundPath, BodyMatch: fmt.Sprintf(`const apiUrl = "%s"`, endpoint), Code: http.StatusOK},
			}...)
		})
		t.Run("playground.js is loaded", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: path.Join(playgroundPath, "playground.js"), BodyMatch: "var TykGraphiqlExplorer", Code: http.StatusOK},
			}...)
		})
		t.Run("should get error on post request to playground path", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{
					Path:         playgroundPath,
					Method:       http.MethodPost,
					BodyNotMatch: `<title>API Playground</title>`,
					BodyMatch:    `"error": "the provided request is empty"`,
					Code:         http.StatusBadRequest,
				},
			}...)
		})
	}

	for _, env := range []string{"on-premise", "cloud"} {
		if env == "cloud" {
			api.Proxy.ListenPath = fmt.Sprintf("/%s/", api.APIID)
			globalConf := g.Gw.GetConfig()
			api.Slug = "someslug"
			globalConf.Cloud = true
			g.Gw.SetConfig(globalConf)
		}

		t.Run(env, func(t *testing.T) {
			t.Run("playground path is empty", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = ""
				run(t, api.Proxy.ListenPath, api, env)
			})

			t.Run("playground path is '/'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/"
				g.Gw.LoadAPI(api)
				_, _ = g.Run(t, []test.TestCase{
					{Path: api.Proxy.ListenPath, BodyMatch: `<link rel="stylesheet" href="playground.css" />`},
					{Path: api.Proxy.ListenPath, BodyMatch: `endpoint: "\\/` + apiName + `\\/"`},
					{Path: api.Proxy.ListenPath + "playground.css", BodyMatch: "body{margin:0;padding:0;font-family:.*"},
				}...)
			})

			t.Run("playground path is '/playground'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/playground"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "playground"), api, env)
			})

			t.Run("playground path is '/ppp'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/ppp"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "/ppp"), api, env)
			})

			t.Run("playground path is '/zzz/'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/zzz/"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "/zzz"), api, env)
			})

			t.Run("playground path is 'aaa'", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "aaa"
				g.Gw.LoadAPI(api)
				run(t, path.Join(api.Proxy.ListenPath, "aaa"), api, env)
			})

		})
	}
}
*/
func TestCORS(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	apis := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "CORS test API"
		spec.APIID = "cors-api"
		spec.Proxy.ListenPath = "/cors-api/"
		spec.CORS.Enable = false
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	}, func(spec *APISpec) {
		spec.Name = "Another API"
		spec.APIID = "another-api"
		spec.Proxy.ListenPath = "/another-api/"
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	})

	headers := map[string]string{
		"Origin": "my-custom-origin",
	}

	headersMatch := map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Expose-Headers": "Custom-Header",
	}

	t.Run("CORS disabled", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("CORS enabled", func(t *testing.T) {
		apis[0].CORS.Enable = true
		g.Gw.LoadAPI(apis...)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusOK},
		}...)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/another-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("oauth endpoints", func(t *testing.T) {
		apis[0].UseOauth2 = true
		apis[0].CORS.Enable = false
		g.Gw.LoadAPI(apis...)

		t.Run("CORS disabled", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})

		t.Run("CORS enabled", func(t *testing.T) {
			apis[0].CORS.Enable = true
			g.Gw.LoadAPI(apis...)

			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})
	})
}

func TestTykRateLimitsStatusOfAPI(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	const (
		quotaMax       = 20
		quotaRemaining = 10
		rate           = 10
		per            = 3
	)

	g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/my-api/"
		spec.UseKeylessAccess = false
	})
	_, key := g.CreateSession(func(s *user.SessionState) {
		s.QuotaMax = quotaMax
		s.QuotaRemaining = quotaRemaining
		s.Rate = rate
		s.Per = per

		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	authHeader := map[string]string{
		"Authorization": key,
	}

	bodyMatch := fmt.Sprintf(`{"quota":{"quota_max":%d,"quota_remaining":%d,"quota_renews":.*},"rate_limit":{"requests":%d,"per_unit":%d}}`,
		quotaMax, quotaRemaining, rate, per)

	_, _ = g.Run(t, test.TestCase{Path: "/my-api/tyk/rate-limits/", Headers: authHeader, BodyMatch: bodyMatch, Code: http.StatusOK})
}
