package dnscache

import (
	"net"
	"time"

	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/cache"
)

// DnsCacheItem represents single record in cache
// SW-REQ-035
type DnsCacheItem struct {
	Addrs []string
}

// DnsCacheStorage is an in-memory cache of auto-purged dns query ip responses
// SW-REQ-035
type DnsCacheStorage struct {
	cache *cache.Cache
}

// SW-REQ-035
func NewDnsCacheStorage(expiration, checkInterval time.Duration) *DnsCacheStorage {
	storage := &DnsCacheStorage{
		cache: cache.NewCache(expiration, checkInterval),
	}
	return storage
}

// Items returns map of non expired dns cache items
// SW-REQ-035
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
// SW-REQ-035
func (dc *DnsCacheStorage) Get(key string) (DnsCacheItem, bool) {
	item, found := dc.cache.Get(key)
	if !found {
		return DnsCacheItem{}, false
	}
	return item.(DnsCacheItem), found
}

// SW-REQ-035
func (dc *DnsCacheStorage) Delete(key string) {
	dc.cache.Delete(key)
}

// FetchItem returns list of ips from cache or resolves them and add to cache
// SW-REQ-035
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

// SW-REQ-035
func (dc *DnsCacheStorage) Set(key string, addrs []string) {
	logger.Debugf("Adding dns record to cache: key=%q, addrs=%q", key, addrs)
	dc.cache.Set(key, DnsCacheItem{addrs}, cache.DefaultExpiration)
}

// Clear deletes all records from cache
// SW-REQ-035
func (dc *DnsCacheStorage) Clear() {
	dc.cache.Flush()
}

// SW-REQ-035
func (dc *DnsCacheStorage) resolveDNSRecord(host string) ([]string, error) {
	return net.LookupHost(host)
}
