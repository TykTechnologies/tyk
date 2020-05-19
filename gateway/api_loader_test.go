package gateway

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/trace"
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
