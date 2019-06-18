package main

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestRedisCacheMiddleware_WithCompressedResponse(t *testing.T) {
	const path = "/compressed"

	globalConf := config.Global()
	globalConf.AnalyticsConfig.EnableDetailedRecording = true
	config.SetGlobal(globalConf)

	ts := newTykTestServer()
	defer ts.Close()

	createAPI := func(withCache bool) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.CacheOptions.EnableCache = withCache
			updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
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
