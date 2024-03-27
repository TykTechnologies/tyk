package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestDeleteAPICache(t *testing.T) {
	t.Run("event", func(t *testing.T) {

		ts := StartTest(nil)
		defer ts.Close()

		specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIDefinition.CacheOptions = apidef.CacheOptions{
				EnableCache:  true,
				CacheTimeout: 120,
			}
			spec.Proxy.ListenPath = "/cache"
		})

		// send requests to cache the API
		// emit event
		n := Notification{
			Command: noticeDeleteAPICache,
			Payload: specs[0].APIID,
			Gw:      ts.Gw,
		}
		ts.Gw.MainNotifier.Notify(n)

	})

}
