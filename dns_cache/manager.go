package dns_cache

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
)

var (
	logger                  = log.Get().WithField("prefix", "dns-cache")
)

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type IDnsCacheManager interface {
	InitDNSCaching(ttl, checkInterval time.Duration)
	WrapDialer(dialer *net.Dialer) dialContextFunc
}

type DnsCacheManager struct {
	DnsCache *DnsCacheStorage
}

func NewDnsCacheManager() *DnsCacheManager {
	return &DnsCacheManager{nil}
}

func (m *DnsCacheManager) WrapDialer(dialer *net.Dialer) dialContextFunc {
	if m.DnsCache == nil {
		return dialer.DialContext
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return m.doCachedDial(dialer, ctx, network, address)
	}
}

func (m *DnsCacheManager) doCachedDial(d *net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	if m.DnsCache == nil {
		return d.DialContext(ctx, network, address)
	}
	
	separator := strings.LastIndex(address, ":")
	ips, err := m.DnsCache.FetchItem(address[:separator])
	
	if err != nil {
		logger.Infof("doCachedDial error: %v. network=%v, address=%v", err.Error(), network, address)
	}

	return d.DialContext(ctx, network, ips[0]+address[separator:])
}

func (m *DnsCacheManager) InitDNSCaching(ttl, checkInterval time.Duration) {
	if m.DnsCache == nil {
		logger.Infof("Initialized dns cache with ttl=%s, duration=%s", ttl, checkInterval)
		m.DnsCache = NewDnsCacheStorage(ttl, checkInterval)
	}
}

func (m *DnsCacheManager) DisposeCache() {
	m.DnsCache.Clear()
	m.DnsCache = nil
}
