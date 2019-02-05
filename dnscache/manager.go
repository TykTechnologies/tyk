package dnscache

import (
	"context"
	"net"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/log"
)

var (
	logger = log.Get().WithField("prefix", "dnscache")
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// IDnsCacheManager is an interface for abstracting interaction with dns cache. Implemented by DnsCacheManager
type IDnsCacheManager interface {
	InitDNSCaching(ttl, checkInterval time.Duration)
	WrapDialer(dialer *net.Dialer) DialContextFunc
	SetCacheStorage(cache IDnsCacheStorage)
	CacheStorage() IDnsCacheStorage
	DisposeCache()
}

// IDnsCacheStorage is an interface for working with cached storage of dns record.
// Wrapped by IDnsCacheManager/DnsCacheManager. Implemented by DnsCacheStorage
type IDnsCacheStorage interface {
	FetchItem(key string) ([]string, error)
	Get(key string) (DnsCacheItem, bool)
	Set(key string, addrs []string)
	Delete(key string)
	Clear()
}

// DnsCacheManager is responsible for in-memory dns query records cache.
// It allows to init dns caching and to hook into net/http dns resolution chain in order to cache query response ip records.
type DnsCacheManager struct {
	cacheStorage IDnsCacheStorage
}

// NewDnsCacheManager returns new empty/non-initialized DnsCacheManager
func NewDnsCacheManager() *DnsCacheManager {
	return &DnsCacheManager{nil}
}

func (m *DnsCacheManager) SetCacheStorage(cache IDnsCacheStorage) {
	m.cacheStorage = cache
}

func (m *DnsCacheManager) CacheStorage() IDnsCacheStorage {
	return m.cacheStorage
}

// WrapDialer returns wrapped version of net.Dialer#DialContext func with hooked up caching of dns queries.
//
// Actual dns server call occures in net.Resolver#LookupIPAddr method,
// linked to net.Dialer instance by net.Dialer#Resolver field
func (m *DnsCacheManager) WrapDialer(dialer *net.Dialer) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return m.doCachedDial(dialer, ctx, network, address)
	}
}

func (m *DnsCacheManager) doCachedDial(d *net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	safeDial := func(addr string, itemKey string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil && itemKey != "" {
			m.cacheStorage.Delete(itemKey)
		}
		return conn, err
	}

	if m.cacheStorage == nil {
		return safeDial(address, "")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return safeDial(address, "")
	}

	ips, err := m.cacheStorage.FetchItem(host)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"network": network,
			"address": address,
		}).Errorf("doCachedDial cachedStorage.FetchItem error: %v. ips=%v", err.Error(), ips)

		return safeDial(ips[0]+":"+port, "")
	}

	return safeDial(ips[0]+":"+port, host)
}

// InitDNSCaching initializes manager's cache storage if it wasn't initialized before with provided ttl, checkinterval values
// Initialized cache storage enables caching of previously hoooked net.Dialer DialContext calls
//
// Otherwise leave storage as is.
func (m *DnsCacheManager) InitDNSCaching(ttl, checkInterval time.Duration) {
	if m.cacheStorage == nil {
		logger.Infof("Initializing dns cache with ttl=%s, duration=%s", ttl, checkInterval)
		storage := NewDnsCacheStorage(ttl, checkInterval)
		m.cacheStorage = IDnsCacheStorage(storage)
	}
}

// DisposeCache clear all entries from cache and disposes/disables caching of dns queries
func (m *DnsCacheManager) DisposeCache() {
	m.cacheStorage.Clear()
	m.cacheStorage = nil
}
