package dnscache

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/TykTechnologies/tyk/v3/config"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/log"
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
	IsCacheEnabled() bool
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
	strategy     config.IPsHandleStrategy
	rand         *rand.Rand
}

// NewDnsCacheManager returns new empty/non-initialized DnsCacheManager
func NewDnsCacheManager(multipleIPsHandleStrategy config.IPsHandleStrategy) *DnsCacheManager {
	manager := &DnsCacheManager{nil, multipleIPsHandleStrategy, nil}
	return manager
}

func (m *DnsCacheManager) SetCacheStorage(cache IDnsCacheStorage) {
	m.cacheStorage = cache
}

func (m *DnsCacheManager) CacheStorage() IDnsCacheStorage {
	return m.cacheStorage
}

func (m *DnsCacheManager) IsCacheEnabled() bool {
	return m.cacheStorage != nil
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

	if !m.IsCacheEnabled() {
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
		logger.WithError(err).WithFields(logrus.Fields{
			"network": network,
			"address": address,
		}).Errorf("doCachedDial cachedStorage.FetchItem error. ips=%v", ips)

		return safeDial(address, "")
	}

	if m.strategy == config.NoCacheStrategy {
		if len(ips) > 1 {
			m.cacheStorage.Delete(host)
			return safeDial(ips[0]+":"+port, "")
		}
	}

	if m.strategy == config.RandomStrategy {
		if len(ips) > 1 {
			ip, _ := m.getRandomIp(ips)
			return safeDial(ip+":"+port, host)
		}
		return safeDial(ips[0]+":"+port, host)
	}

	return safeDial(ips[0]+":"+port, host)
}

func (m *DnsCacheManager) getRandomIp(ips []string) (string, error) {
	if m.strategy != config.RandomStrategy {
		return "", fmt.Errorf(
			"getRandomIp can be called only with %v strategy. strategy=%v",
			config.RandomStrategy, m.strategy)
	}

	if m.rand == nil {
		source := rand.NewSource(time.Now().Unix())
		m.rand = rand.New(source)
	}

	ip := ips[m.rand.Intn(len(ips))]

	return ip, nil
}

// InitDNSCaching initializes manager's cache storage if it wasn't initialized before with provided ttl, checkinterval values
// Initialized cache storage enables caching of previously hoooked net.Dialer DialContext calls
//
// Otherwise leave storage as is.
func (m *DnsCacheManager) InitDNSCaching(ttl, checkInterval time.Duration) {
	if !m.IsCacheEnabled() {
		logger.Infof("Initializing dns cache with ttl=%s, duration=%s", ttl, checkInterval)
		storage := NewDnsCacheStorage(ttl, checkInterval)
		m.SetCacheStorage(IDnsCacheStorage(storage))
	}
}

// DisposeCache clear all entries from cache and disposes/disables caching of dns queries
func (m *DnsCacheManager) DisposeCache() {
	m.cacheStorage.Clear()
	m.cacheStorage = nil
}
