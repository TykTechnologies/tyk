package regression

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
)

func Test_Issue11585_DeleteAPICacheSignal(t *testing.T) {
	t.Run("redis event", func(t *testing.T) {
		ts := gateway.StartTest(nil)
		t.Cleanup(ts.Close)

		api := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
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
		n := gateway.Notification{
			Command: gateway.NoticeDeleteAPICache,
			Payload: api.APIID,
			Gw:      ts.Gw,
		}
		ts.Gw.MainNotifier.Notify(n)

		time.Sleep(time.Millisecond * 50)
		scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, true)
	})

	t.Run("rpc", func(t *testing.T) {
		ts := gateway.StartTest(nil)
		t.Cleanup(ts.Close)

		rpcListener := gateway.RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
			Gw:               ts.Gw,
		}

		api := ts.Gw.BuildAndLoadAPI(func(spec *gateway.APISpec) {
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

		buildStringEvent := func(apiID string) string {
			return fmt.Sprintf("%s:%s", apiID, gateway.NoticeDeleteAPICache.String())
		}

		t.Run("different api id in event", func(t *testing.T) {
			scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, false)
			rpcListener.ProcessKeySpaceChanges([]string{buildStringEvent("non-existing-api-id")}, api.OrgID)
			scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, false)
		})

		t.Run("same api id in event", func(t *testing.T) {
			scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, false)
			rpcListener.ProcessKeySpaceChanges([]string{buildStringEvent(api.APIID)}, api.OrgID)
			scanCacheKeys(t, ts.Gw.StorageConnectionHandler, api.APIID, true)
		})
	})
}

func scanCacheKeys(t *testing.T, storageConnHandler *storage.ConnectionHandler, apiID string, expectEmtpy bool) {
	t.Helper()
	store := storage.RedisCluster{IsCache: true, ConnectionHandler: storageConnHandler}
	cacheKeys, err := store.ScanKeys(fmt.Sprintf("cache-%s*", apiID))
	assert.NoError(t, err)
	assert.Equal(t, expectEmtpy, len(cacheKeys) == 0)
}
