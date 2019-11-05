package gateway

import (
	"testing"

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
		var s string
		trace.SetInit(func(name string, service string, opts map[string]interface{}, logger trace.Logger) (trace.Tracer, error) {
			s = service
			return trace.NoopTracer{}, nil
		})
		name := "trace"
		BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Name = name
				spec.UseOauth2 = true
			},
		)
		if name != s {
			ts.Errorf("expected %s got %s", name, s)
		}
	})
}
