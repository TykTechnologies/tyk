package storage

import (
	"net"
	"reflect"
	"time"

	"github.com/pmylund/go-cache"
	"fmt"
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
	fmt.Printf("NewDnsCacheStorage: %s, %s\n", expiration, checkInterval)
	storage := &DnsCacheStorage{cache.New(expiration, checkInterval)}
	storage.cache.OnEvicted(func(s string, i interface{}) {
		fmt.Printf("Evicted: %#v %s %s\n", i,s, time.Now())
	})
	return storage
}

//Return non expired items from cache
func (dc *DnsCacheStorage) Items() map[string]DnsCacheItem {
	var nonExpiredItems map[string]cache.Item = dc.cache.Items()

	items := map[string]DnsCacheItem{}

	for k, v := range nonExpiredItems {
		if v.Expired() {
			continue
		}
		addrs, _ := v.Object.([]string)
		items[k] = DnsCacheItem{addrs}
	}

	return items
}

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

func (dc *DnsCacheStorage) Clear() {
	for key := range dc.cache.Items() {
		dc.cache.Delete(key)
	}
}

func (dc *DnsCacheStorage) resolveDNSRecord(host string) ([]string, error) {
	return net.LookupHost(host)
}
