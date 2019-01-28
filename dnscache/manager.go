package dnscache

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/log"
)

var (
	logger = log.Get().WithField("prefix", "dns-cache")
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

//IDnsCacheManager is an interface for abstracting interaction with dns cache. Implemented by DnsCacheManager
type IDnsCacheManager interface {
	InitDNSCaching(ttl, checkInterval time.Duration)
	WrapDialer(dialer *net.Dialer) DialContextFunc
	SetCacheStorage(cache IDnsCacheStorage)
	CacheStorage()
}

//IDnsCacheStorage is an interface for working with cached storage of dns record.
// Wrapped by IDnsCacheManager/DnsCacheManager. Implemented by DnsCacheStorage
type IDnsCacheStorage interface {
	FetchItem(key string) ([]string, error)
	Get(key string) (DnsCacheItem, bool)
	Clear()
}


//DnsCacheManager is responsible for in-memory dns query records cache.
//It allows to init dns caching and to hook into net/http dns resolution chain in order to cache query response ip records.
type DnsCacheManager struct {
	cacheStorage IDnsCacheStorage
}

func NewDnsCacheManager() *DnsCacheManager {
	return &DnsCacheManager{nil}
}

func (m *DnsCacheManager) SetCacheStorage(cache IDnsCacheStorage) {
	m.cacheStorage = cache
}

func (m *DnsCacheManager) CacheStorage() IDnsCacheStorage {
	return m.cacheStorage
}

func (m *DnsCacheManager) WrapDialer(dialer *net.Dialer) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return m.doCachedDial(dialer, ctx, network, address)
	}
}

func (m *DnsCacheManager) doCachedDial(d *net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	if m.cacheStorage == nil {
		return d.DialContext(ctx, network, address)
	}

	separator := strings.LastIndex(address, ":")
	ips, err := m.cacheStorage.FetchItem(address[:separator])

	if err != nil {
		logger.Infof("doCachedDial error: %v. network=%v, address=%v", err.Error(), network, address)
	}

	return d.DialContext(ctx, network, ips[0]+address[separator:])
}

func (m *DnsCacheManager) InitDNSCaching(ttl, checkInterval time.Duration) {
	if m.cacheStorage == nil {
		logger.Infof("Initializing dns cache with ttl=%s, duration=%s", ttl, checkInterval)
		storage := NewDnsCacheStorage(ttl, checkInterval)
		m.cacheStorage = IDnsCacheStorage(storage)
	}
}

func (m *DnsCacheManager) DisposeCache() {
	m.cacheStorage.Clear()
	m.cacheStorage = nil
}
