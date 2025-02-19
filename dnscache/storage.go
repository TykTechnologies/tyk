package dnscache

import (
	"net"
	"time"

	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/cache"
)

// DnsCacheItem represents single record in cache
type DnsCacheItem struct {
	Addrs []string
}

// DnsCacheStorage is an in-memory cache of auto-purged dns query ip responses
type DnsCacheStorage struct {
	cache *cache.Cache
}

func NewDnsCacheStorage(expiration, checkInterval time.Duration) *DnsCacheStorage {
	storage := &DnsCacheStorage{
		cache: cache.NewCache(expiration, checkInterval),
	}
	return storage
}

// Items returns map of non expired dns cache items
func (dc *DnsCacheStorage) Items(includeExpired bool) map[string]DnsCacheItem {
	var allItems = dc.cache.Items()

	nonExpiredItems := map[string]DnsCacheItem{}

	for k, v := range allItems {
		if !includeExpired && v.Expired() {
			continue
		}
		nonExpiredItems[k] = v.Object.(DnsCacheItem)
	}

	return nonExpiredItems
}

// Get returns non expired item from cache
func (dc *DnsCacheStorage) Get(key string) (DnsCacheItem, bool) {
	item, found := dc.cache.Get(key)
	if !found {
		return DnsCacheItem{}, false
	}
	return item.(DnsCacheItem), found
}

func (dc *DnsCacheStorage) Delete(key string) {
	dc.cache.Delete(key)
}

// FetchItem returns list of ips from cache or resolves them and add to cache
func (dc *DnsCacheStorage) FetchItem(hostName string) ([]string, error) {
	if hostName == "" {
		return nil, fmt.Errorf("hostName can't be empty. hostName=%v", hostName)
	}

	item, ok := dc.Get(hostName)
	if ok {
		logger.WithFields(logrus.Fields{
			"hostName": hostName,
			"addrs":    item.Addrs,
		}).Debug("Dns record was populated from cache")
		return item.Addrs, nil
	}

	addrs, err := dc.resolveDNSRecord(hostName)
	if err != nil {
		return nil, err
	}

	dc.Set(hostName, addrs)
	return addrs, nil
}

func (dc *DnsCacheStorage) Set(key string, addrs []string) {
	logger.Debugf("Adding dns record to cache: key=%q, addrs=%q", key, addrs)
	dc.cache.Set(key, DnsCacheItem{addrs}, cache.DefaultExpiration)
}

// Clear deletes all records from cache
func (dc *DnsCacheStorage) Clear() {
	dc.cache.Flush()
}

func (dc *DnsCacheStorage) resolveDNSRecord(host string) ([]string, error) {
	return net.LookupHost(host)
}
