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
//type StorageBuiderFunc func() (*IDnsCacheStorage, error)

type IDnsCacheManager interface {
	InitDNSCaching(ttl, checkInterval time.Duration)
	WrapDialer(dialer *net.Dialer) DialContextFunc
	SetCacheStorage(cache IDnsCacheStorage)
	CacheStorage()
}

type IDnsCacheStorage interface {
	FetchItem(key string) ([]string, error)
	Get(key string) (DnsCacheItem, bool)
	Clear()
}

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
		logger.Infof("Initialized dns cache with ttl=%s, duration=%s", ttl, checkInterval)
		storage := NewDnsCacheStorage(ttl, checkInterval)
		m.cacheStorage = IDnsCacheStorage(storage)
	}
}

func (m *DnsCacheManager) DisposeCache() {
	m.cacheStorage.Clear()
	m.cacheStorage = nil
}
