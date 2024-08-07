package gateway

import (
	"fmt"

	"github.com/TykTechnologies/tyk/storage"
)

func (gw *Gateway) invalidateAPICache(apiID string) bool {
	store, err := storage.NewStorageHandler(
		storage.REDIS_CLUSTER,
		storage.WithConnectionHandler(gw.StorageConnectionHandler),
		storage.IsCache(true),
	)

	if err != nil {
		log.WithError(err).Error("could not create storage handler")
		return false
	}

	return store.DeleteScanMatch(fmt.Sprintf("cache-%s*", apiID))
}
