package rate_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
)

func buildPathRateLimitAPI(ts *Test, tb testing.TB, pathName string, rate, per int64) {
	tb.Helper()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/ratelimit/"
		spec.Proxy.StripListenPath = true

		spec.GlobalRateLimit.Rate = 15
		spec.GlobalRateLimit.Per = float64(per)

		version := spec.VersionData.Versions["v1"]
		versionJSON := []byte(fmt.Sprintf(`{
                        "use_extended_paths": true,
                        "extended_paths": {
                                "rate_limit": [{
                                        "method": "GET",
        				"rate": %d,
                                        "per": %d
                                }]
                        }
                    }`, rate, per))
		err := json.Unmarshal(versionJSON, &version)
		assert.NoError(tb, err)

		version.ExtendedPaths.RateLimit[0].Path = pathName
		spec.VersionData.Versions["v1"] = version

	})
}

func TestPerAPILimit(t *testing.T) {
	t.Run("miss per-endpoint rate limit", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		forPath := "/" + uuid.New()
		testPath := "/anything"

		buildPathRateLimitAPI(ts, t, forPath, 30, 60)

		// single request
		_, _ = ts.Run(t, test.TestCase{
			Path:      "/ratelimit" + testPath,
			BodyMatch: fmt.Sprintf(`"Url":"%s"`, testPath),
		})

		// and 50 more
		var ok, failed int = 1, 0
		for i := 0; i < 50; i++ {
			res, err := ts.Run(t, test.TestCase{
				Path: "/ratelimit" + testPath,
			})

			assert.NoError(t, err)
			if res.Body != nil {
				res.Body.Close()
			}

			if res.StatusCode == 200 {
				ok++
				continue
			}
			failed++
		}

		// assert global limit
		assert.Equal(t, 15, ok)
	})

	t.Run("hit per-endpoint rate limit", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		forPath := "/" + uuid.New()
		testPath := forPath

		buildPathRateLimitAPI(ts, t, forPath, 30, 60)

		// single request
		_, _ = ts.Run(t, test.TestCase{
			Path:      "/ratelimit" + testPath,
			BodyMatch: fmt.Sprintf(`"Url":"%s"`, testPath),
		})

		// and 50 more
		var ok, failed int = 1, 0
		for i := 0; i < 50; i++ {
			res, err := ts.Run(t, test.TestCase{
				Path: "/ratelimit" + testPath,
			})

			assert.NoError(t, err)
			if res.Body != nil {
				res.Body.Close()
			}

			if res.StatusCode == 200 {
				ok++
				continue
			}
			failed++
		}

		// assert per-endpoint limit
		assert.Equal(t, 30, ok)
	})
}
