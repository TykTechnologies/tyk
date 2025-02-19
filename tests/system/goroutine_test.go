package system_test

import (
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/debug2"
	"github.com/TykTechnologies/tyk/test"
)

func TestReloadGoroutineLeakWithTest(t *testing.T) {
	test.Flaky(t)

	newRecord := func() *debug2.Record {
		result := debug2.NewRecord()
		result.SetIgnores([]string{
			"runtime/pprof.writeRuntimeProfile",
			"/root/go/pkg/mod/github.com/!tyk!technologies/leakybucket@v0.0.0-20170301023702-71692c943e3c/memorycache/cache.go:69",
			"/root/go/pkg/mod/github.com/pmylund/go-cache@v2.1.0+incompatible/cache.go:1079",
			"/root/tyk/tyk/gateway/distributed_rate_limiter.go:31",
			"/root/tyk/tyk/gateway/redis_signals.go:68",
		})

		return result
	}

	before := newRecord()
	require.Less(t, before.Count(), 100, "before count over a 100, leak: %s", before)

	ts := gateway.StartTest(nil)
	ts.Close()

	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	final := newRecord().Since(before)
	assert.Equal(t, 0, final.Count(), "final count not zero: %s", final)
}

func TestReloadGoroutineLeakWithCircuitBreaker(t *testing.T) {
	test.Flaky(t)

	ts := gateway.StartTest(nil)
	t.Cleanup(ts.Close)

	newRecord := func() *debug2.Record {
		result := debug2.NewRecord()
		result.SetIgnores([]string{
			"runtime/pprof.writeRuntimeProfile",
			"/root/tyk/tyk/gateway/reverse_proxy.go:223",
			"/root/tyk/tyk/gateway/api_definition.go:1025",
			"/root/tyk/tyk/gateway/distributed_rate_limiter.go:31",
			"/root/go/pkg/mod/github.com/pmylund/go-cache@v2.1.0+incompatible/cache.go:1079",
			"/root/go/pkg/mod/github.com/!tyk!technologies/circuitbreaker@v2.2.2+incompatible/circuitbreaker.go:202",
		})

		return result
	}

	globalConf := ts.Gw.GetConfig()
	globalConf.EnableJSVM = false
	ts.Gw.SetConfig(globalConf)

	stage1 := newRecord()

	specs := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
		spec.Proxy.ListenPath = "/"
		gateway.UpdateAPIVersion(spec, "v1", func(version *apidef.VersionInfo) {
			version.ExtendedPaths = apidef.ExtendedPathsSet{
				CircuitBreaker: []apidef.CircuitBreakerMeta{
					{
						Path:                 "/",
						Method:               http.MethodGet,
						ThresholdPercent:     0.5,
						Samples:              5,
						ReturnToServiceAfter: 10,
					},
				},
			}
		})
	})

	ts.Gw.LoadAPI(specs...) // just doing globalGateway.DoReload() doesn't load anything as BuildAndLoadAPI cleans up folder with API specs

	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	final := newRecord().Since(stage1)
	assert.Equal(t, 0, final.Count(), "final count not zero: %s", final)
}
