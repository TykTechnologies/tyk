package gateway

import (
	"fmt"

	"github.com/TykTechnologies/tyk/storage"
)

// Implements: SW-REQ-126
func (gw *Gateway) invalidateAPICache(apiID string) bool {
	store := storage.RedisCluster{IsCache: true, ConnectionHandler: gw.StorageConnectionHandler}
	store.Connect()

	return store.DeleteScanMatch(fmt.Sprintf("cache-%s*", apiID))
}
