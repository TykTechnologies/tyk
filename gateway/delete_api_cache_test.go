package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestDeleteAPICache(t *testing.T) {
	t.Run("event", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = true
			spec.Proxy.ListenPath = "/cache-api/"
			spec.CacheOptions = apidef.CacheOptions{
				EnableCache:          true,
				CacheTimeout:         120,
				CacheAllSafeRequests: true,
			}
		})[0]

		// hit an api to create cache
		_, _ = ts.Run(t, test.TestCase{
			Path: "/cache-api/",
			Code: http.StatusOK,
		})

		// emit event
		n := Notification{
			Command: noticeDeleteAPICache,
			Payload: api.APIID,
			Gw:      ts.Gw,
		}
		ts.Gw.MainNotifier.Notify(n)

		time.Sleep(time.Millisecond * 50)
		scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, true)
	})
}
