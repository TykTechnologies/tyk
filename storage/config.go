package storage

import (
	"github.com/TykTechnologies/tyk/config"
)

func getStorageConfig(isCache, isAnalytics bool, conf config.Config) config.StorageOptionsConf {
	if isCache && conf.EnableSeperateCacheStore {
		return conf.CacheStorage
	}
	if isAnalytics && conf.EnableAnalytics && conf.EnableSeperateAnalyticsStore {
		return conf.AnalyticsStorage
	}
	return conf.Storage
}
