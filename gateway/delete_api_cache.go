package gateway

import (
	"github.com/TykTechnologies/tyk/storage"
)

func (gw *Gateway) invalidateAPICache(apiID string) bool {
	keyPrefix := "cache-" + apiID
	matchPattern := keyPrefix + "*"
	store := storage.RedisCluster{IsCache: true, ConnectionHandler: gw.StorageConnectionHandler}
	return store.DeleteScanMatch(matchPattern)
}
