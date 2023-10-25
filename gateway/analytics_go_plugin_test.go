package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestGoAnalyticsPlugin(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	t.Run("just enabled without other parameters set", func(t *testing.T) {
		g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.AnalyticsPlugin.Enabled = true
		})

		_, _ = g.Run(t, test.TestCase{Path: "/", Code: http.StatusOK})
	})
}
