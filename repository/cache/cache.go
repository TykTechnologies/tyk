package cache

import (
	"errors"
	"fmt"

	"github.com/TykTechnologies/tyk/storage"
)

const (
	cacheFormat        = "cache-%s"
	matchPatternFormat = cacheFormat + "*"
)

type Cache struct{}

func (Cache) Invalidate(apiId string) error {
	store := storage.RedisCluster{KeyPrefix: fmt.Sprintf(cacheFormat, apiId), IsCache: true}
	if ok := store.DeleteScanMatch(fmt.Sprintf(matchPatternFormat, apiId)); !ok {
		return errors.New("scan/delete failed")
	}

	return nil
}
