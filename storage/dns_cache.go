package storage

import (
	"errors"
	"net"
	"time"

	cache "github.com/pmylund/go-cache"
)

type DnsCacheItem struct {
	names []string
}

type DnsCacheStorage struct {
	cache *cache.Cache
}

func NewDnsCacheStorage(expirationTime time.Duration) *DnsCacheStorage {
	return &DnsCacheStorage{cache.New(cache.NoExpiration, expirationTime)}
}

func (dc *DnsCacheStorage) FetchItem(key string) ([]string, error) {
	item, ok := dc.cache.Get(key)
	if ok {
		result, _ := item.(DnsCacheItem)
		return result.names, nil
	}

	addrs, err := net.LookupHost(key)
	if err != nil {
		return nil, err
	}

	cachedItem := DnsCacheItem{addrs}
	dc.Set(key, cachedItem)
	return addrs, nil
}

func (dc *DnsCacheStorage) Set(key string, item DnsCacheItem) error {
	dc.cache.Set(key, item, cache.DefaultExpiration)
	return errors.New("Not implemented")
}
