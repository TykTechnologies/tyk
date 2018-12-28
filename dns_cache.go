package main

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/storage"
)

var (
	dnsCache *storage.DnsCacheStorage
)

// type CachedDialer struct {
// 	net.Dialer

// 	cacheStorage storage.DnsCacheStorage
// }

// func NewCachedDialer(d net.Dialer, s storage.DnsCacheStorage) *CachedDialer {
// 	return &CachedDialer{d, s}
// }

// func (cd *CachedDialer) DoCachedDial(ctx context.Context, network, address string) (net.Conn, error) {
// 	return doCachedDial(d.Dialer, ctx, network, address)
// }

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func wrapDialer(dialer *net.Dialer) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return doCachedDial(dialer, ctx, network, address)
	}
}

func doCachedDial(d *net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	separator := strings.LastIndex(address, ":")
	ips, err := dnsCache.FetchItem(address[:separator])
	log.Infoln("err: %v; got ips: %s for %v. Separator: %v", err, ips, address, separator)

	return d.DialContext(ctx, network, ips[0]+address[separator:])
}

func initDNSCaching(ttl, checkInterval int) {
	if dnsCache != nil {
		dnsCache = storage.NewDnsCacheStorage(time.Duration(ttl), time.Duration(checkInterval))
	}
}
