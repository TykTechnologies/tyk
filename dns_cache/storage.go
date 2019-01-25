package dns_cache

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
	storage := DnsCacheStorage{cache.New(expiration, checkInterval)}
	return &storage
}

//Return map of non expired dns cache items
func (dc *DnsCacheStorage) Items(includeExpired bool) map[string]DnsCacheItem {
	var nonExpiredItems map[string]cache.Item = dc.cache.Items()

	items := map[string]DnsCacheItem{}

	for k, v := range nonExpiredItems {
		if !includeExpired && v.Expired() {
			continue
		}
		items[k] = v.Object.(DnsCacheItem)
	}

	return items
}

//Returns non expired item from cache
func (dc *DnsCacheStorage) Get(key string) (DnsCacheItem, bool) {
	item, found := dc.cache.Get(key)
	if !found {
		return DnsCacheItem{}, false
	}
	return item.(DnsCacheItem), found
}

func (dc *DnsCacheStorage) FetchItem(key string) ([]string, error) {
	item, ok := dc.cache.Get(key)
	if ok {
		result, _ := item.(DnsCacheItem)
		logger.Debugf("Dns record was populated from cache: key=%q, addrs=%q", key, result.addrs)
		return result.addrs, nil
	}

	addrs, err := dc.resolveDNSRecord(key)
	if err != nil {
		return nil, err
	}

	dc.Set(key, addrs)
	return addrs, nil
}

func (dc *DnsCacheStorage) Set(key string, addrs []string) {
	logger.Debugf("Adding dns record to cache: key=%q, addrs=%q", key, addrs)
	dc.cache.Set(key, DnsCacheItem{addrs}, cache.DefaultExpiration)
}

func (dc *DnsCacheStorage) Clear() {
	dc.cache.Flush()
}

func (dc *DnsCacheStorage) resolveDNSRecord(host string) ([]string, error) {
	return net.LookupHost(host)
}
