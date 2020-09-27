package gateway

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/v3/config"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/v3/test"

	"github.com/TykTechnologies/tyk/v3/trace"
)

func TestOpenTracing(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	trace.SetupTracing("test", nil)
	defer trace.Close()

	t.Run("ensure the manager is enabled", func(ts *testing.T) {
		if !trace.IsEnabled() {
			ts.Error("expected tracing manager should be enabled")
		}
	})

	t.Run("ensure services are initialized", func(ts *testing.T) {
		var s atomic.Value
		trace.SetInit(func(name string, service string, opts map[string]interface{}, logger trace.Logger) (trace.Tracer, error) {
			s.Store(service)
			return trace.NoopTracer{}, nil
		})
		name := "trace"
		BuildAndLoadAPI(
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
			ts.Errorf("expected %s got %s", name, n)
		}
	})
}

func TestInternalAPIUsage(t *testing.T) {
	g := StartTest()
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

	LoadAPI(internal, normal)

	t.Run("with name", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})

	t.Run("with api id", func(t *testing.T) {
		normal.Proxy.TargetURL = fmt.Sprintf("tyk://%s", internal.APIID)

		LoadAPI(internal, normal)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/normal-api", Code: http.StatusOK},
		}...)
	})
}

func TestFuzzyFindAPI(t *testing.T) {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "IgnoreCase"
		spec.APIID = "123456"
		spec.Proxy.ListenPath = "/"
	})

	spec := fuzzyFindAPI("ignoreCase")
	assert.Equal(t, "123456", spec.APIID)
}

func TestGraphQLPlayground(t *testing.T) {
	g := StartTest()
	defer g.Close()

	defer ResetTestConfig()

	const apiName = "graphql-api"

	api := BuildAPI(func(spec *APISpec) {
		spec.APIID = "APIID"
		spec.Proxy.ListenPath = fmt.Sprintf("/%s/", apiName)
		spec.GraphQL.Enabled = true
		spec.GraphQL.GraphQLPlayground.Enabled = true
	})[0]

	for _, env := range []string{"on-premise", "cloud"} {
		if env == "cloud" {
			api.Proxy.ListenPath = fmt.Sprintf("/%s/", api.APIID)
			api.Slug = apiName
			globalConf := config.Global()
			globalConf.Cloud = true
			config.SetGlobal(globalConf)
		}

		t.Run(env, func(t *testing.T) {
			t.Run("path is empty", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = ""
				LoadAPI(api)
				_, _ = g.Run(t, []test.TestCase{
					{Path: api.Proxy.ListenPath, BodyMatch: `<link rel="stylesheet" href="playground.css" />`},
					{Path: api.Proxy.ListenPath, BodyMatch: `endpoint: "\\/` + apiName + `\\/"`},
					{Path: api.Proxy.ListenPath + "playground.css", BodyMatch: "body{margin:0;padding:0;font-family:.*"},
				}...)
			})

			t.Run("path is /", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/"
				LoadAPI(api)
				_, _ = g.Run(t, []test.TestCase{
					{Path: api.Proxy.ListenPath, BodyMatch: `<link rel="stylesheet" href="playground.css" />`},
					{Path: api.Proxy.ListenPath, BodyMatch: `endpoint: "\\/` + apiName + `\\/"`},
					{Path: api.Proxy.ListenPath + "playground.css", BodyMatch: "body{margin:0;padding:0;font-family:.*"},
				}...)
			})

			t.Run("path is /playground", func(t *testing.T) {
				api.GraphQL.GraphQLPlayground.Path = "/playground"
				LoadAPI(api)
				_, _ = g.Run(t, []test.TestCase{
					{Path: api.Proxy.ListenPath + "playground", BodyMatch: `<link rel="stylesheet" href="playground/playground.css" />`},
					{Path: api.Proxy.ListenPath + "playground", BodyMatch: `endpoint: "\\/` + apiName + `\\/"`},
					{Path: api.Proxy.ListenPath + "playground/playground.css", BodyMatch: "body{margin:0;padding:0;font-family:.*"},
				}...)
			})
		})
	}
}
