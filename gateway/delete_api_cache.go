package gateway

import (
	"fmt"

	"github.com/TykTechnologies/tyk/storage"
)

func (gw *Gateway) invalidateAPICache(apiID string) bool {
	store := storage.RedisCluster{IsCache: true, RedisController: gw.RedisController}
	return store.DeleteScanMatch(fmt.Sprintf("cache-%s*", apiID))
}
