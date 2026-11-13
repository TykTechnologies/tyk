package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

func TestAPISpecIsMCPAggregatorRequiresTheExtension(t *testing.T) {
	t.Parallel()

	assert.True(t, mcpAggregatorSpec("company-tools", "acme", aggregated("github-mcp", "github")).IsMCPAggregator())

	withoutExtension := mcpAggregatorSpec("loop-to-api-named-mcp-aggregator", "acme")
	withoutExtension.OAS.RemoveTykMCPAggregatorExtension()
	assert.False(t, withoutExtension.IsMCPAggregator())
	assert.True(t, withoutExtension.IsMCPManaged())
}

func TestClassicAPILoopingToAPINamedMCPAggregatorStillProxies(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("reached-target")); err != nil {
			t.Errorf("w.Write: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)

	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "loop-target"
			spec.Name = "mcp-aggregator"
			spec.Proxy.ListenPath = "/loop-target/"
			spec.Proxy.TargetURL = upstream.URL
			spec.UseKeylessAccess = true
		},
		func(spec *APISpec) {
			spec.APIID = "looper"
			spec.Name = "looper"
			spec.Proxy.ListenPath = "/looper/"
			spec.Proxy.TargetURL = oas.MCPAggregatorTargetURL
			spec.UseKeylessAccess = true
		},
	)

	looper := ts.Gw.getApiSpec("looper")
	require.NotNil(t, looper)
	assert.False(t, looper.IsMCPAggregator())
	assert.False(t, looper.IsMCPManaged())

	_, _ = ts.Run(t, test.TestCase{Method: http.MethodGet, Path: "/looper/", Code: http.StatusOK, BodyMatch: "reached-target"})
}
