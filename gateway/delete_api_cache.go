package gateway

import (
	"fmt"

	redisCluster "github.com/TykTechnologies/tyk/storage/redis-cluster"
)

func (gw *Gateway) invalidateAPICache(apiID string) bool {
	store := redisCluster.RedisCluster{IsCache: true, ConnectionHandler: gw.StorageConnectionHandler}
	return store.DeleteScanMatch(fmt.Sprintf("cache-%s*", apiID))
}
