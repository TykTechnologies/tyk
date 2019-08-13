package gateway

import (
	"testing"

	"github.com/anuvu/tyk/apidef"
	"github.com/anuvu/tyk/config"
	"github.com/anuvu/tyk/test"
)

func TestRedisCacheMiddleware_WithCompressedResponse(t *testing.T) {
	const path = "/compressed"

	globalConf := config.Global()
	globalConf.AnalyticsConfig.EnableDetailedRecording = true
	config.SetGlobal(globalConf)

	ts := StartTest()
	defer ts.Close()

	createAPI := func(withCache bool) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.CacheOptions.EnableCache = withCache
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.Cached = []string{path}
			})
		})
	}

	t.Run("without cache", func(t *testing.T) {
		createAPI(false)

		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
	})

	t.Run("with cache", func(t *testing.T) {
		createAPI(true)

		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
	})

}
