package storage

import (
	"net"
	"reflect"
	"time"

	cache "github.com/pmylund/go-cache"
)

type DnsCacheItem struct {
	addrs []string
}

func (item *DnsCacheItem) IsEqualsTo(addrs []string) bool {
	return reflect.DeepEqual(item.addrs, addrs)
}

type DnsCacheStorage struct {
	cache *cache.Cache
}

func NewDnsCacheStorage(expiration, checkInterval time.Duration) *DnsCacheStorage {
	return &DnsCacheStorage{cache.New(expiration, checkInterval)}
}

func (dc *DnsCacheStorage) Items() map[string]DnsCacheItem {
	nonExpiredItems := dc.cache.Items()
	items := make(map[string]DnsCacheItem, len(nonExpiredItems))

	for k, v := range nonExpiredItems {
		addrs, _ := v.Object.([]string)
		items[k] = DnsCacheItem{addrs}
	}

	return items
}

func (dc *DnsCacheStorage) Get(key string) (DnsCacheItem, bool) {
	item, ok := dc.cache.Get(key)
	return item.(DnsCacheItem), ok
}

func (dc *DnsCacheStorage) FetchItem(key string) ([]string, error) {
	item, ok := dc.cache.Get(key)
	if ok {
		log.Warnln("---!!!Lookup from cache!!!---")
		result, _ := item.(DnsCacheItem)
		return result.addrs, nil
	}

	addrs, err := dc.resolveDNSRecord(key)
	if err != nil {
		return nil, err
	}

	cachedItem := DnsCacheItem{addrs}
	dc.Set(key, cachedItem)
	return addrs, nil
}

func (dc *DnsCacheStorage) Set(key string, item DnsCacheItem) {
	dc.cache.Set(key, item, cache.DefaultExpiration)
}

func (dc *DnsCacheStorage) resolveDNSRecord(host string) ([]string, error) {
	return net.LookupHost(host)
}
