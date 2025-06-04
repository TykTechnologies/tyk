package rate_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"

	. "github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
)

func buildPathRateLimitAPI(tb testing.TB, gw *Gateway, per int64, rateLimits []apidef.RateLimitMeta) {
	tb.Helper()

	gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/ratelimit/"
		spec.Proxy.StripListenPath = true

		spec.GlobalRateLimit.Rate = 15
		spec.GlobalRateLimit.Per = float64(per)

		version := spec.VersionData.Versions["v1"]
		version.UseExtendedPaths = true
		version.ExtendedPaths.RateLimit = rateLimits
		spec.VersionData.Versions["v1"] = version

	})
}

func testRateLimit(tb testing.TB, ts *Test, testPath string, testMethod string, want int) {
	tb.Helper()

	// single request
	_, _ = ts.Run(tb, test.TestCase{
		Path:   "/ratelimit" + testPath,
		Method: testMethod,
		BodyMatchFunc: func(bytes []byte) bool {
			res := map[string]any{}
			err := json.Unmarshal(bytes, &res)
			assert.NoError(tb, err)
			return assert.Equal(tb, testPath, res["Url"]) && assert.Equal(tb, testMethod, res["Method"])
		},
	})

	// and 50 more
	var ok, failed int = 1, 0
	for i := 0; i < 50; i++ {
		res, err := ts.Run(tb, test.TestCase{
			Path:   "/ratelimit" + testPath,
			Method: testMethod,
		})

		assert.NoError(tb, err)
		if res.Body != nil {
			assert.NoError(tb, res.Body.Close())
		}

		if res.StatusCode == 200 {
			ok++
			continue
		}
		failed++
	}

	// assert global limit
	assert.Equal(tb, want, ok)
}

func TestPerAPILimit(t *testing.T) {
	t.Run("miss per-endpoint rate limit", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		forPath := "/" + uuid.New()
		testPath := "/miss"

		rateLimits := []apidef.RateLimitMeta{
			{
				Method: http.MethodGet,
				Path:   forPath,
				Rate:   30,
				Per:    60,
			},
		}
		buildPathRateLimitAPI(t, ts.Gw, 60, rateLimits)
		testRateLimit(t, ts, testPath, http.MethodGet, 15)
	})

	t.Run("hit per-endpoint rate limit", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		forPath := "/" + uuid.New()
		testPath := forPath

		rateLimits := []apidef.RateLimitMeta{
			{
				Method: http.MethodGet,
				Path:   forPath,
				Rate:   30,
				Per:    60,
			},
		}
		buildPathRateLimitAPI(t, ts.Gw, 60, rateLimits)
		testRateLimit(t, ts, testPath, http.MethodGet, 30)
	})

	t.Run("[TT-12990][regression] hit per-endpoint per-method rate limit", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		forPath := "/anything/" + uuid.New()
		testPath := forPath
		rateLimits := []apidef.RateLimitMeta{
			{
				Method: http.MethodGet,
				Path:   forPath,
				Rate:   20,
				Per:    60,
			},
			{
				Method: http.MethodPost,
				Path:   forPath,
				Rate:   30,
				Per:    60,
			},
		}
		buildPathRateLimitAPI(t, ts.Gw, 60, rateLimits)
		testRateLimit(t, ts, testPath, http.MethodGet, 20)
		testRateLimit(t, ts, testPath, http.MethodPost, 30)
	})
}
