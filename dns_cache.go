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

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func wrapDialer(dialer *net.Dialer) dialContextFunc {
	if dnsCache == nil {
		return dialer.DialContext
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return doCachedDial(dialer, ctx, network, address)
	}
}

func doCachedDial(d *net.Dialer, ctx context.Context, network, address string) (net.Conn, error) {
	separator := strings.LastIndex(address, ":")
	ips, err := dnsCache.FetchItem(address[:separator])
	if err != nil {
		log.Infoln("doCachedDial error: %v. network=%v, address=%v", err.Error(), network, address)
	}

	return d.DialContext(ctx, network, ips[0]+address[separator:])
}

func initDNSCaching(ttl, checkInterval time.Duration) {
	if dnsCache == nil {
		log.Infoln("Initialized dns cache with ttl=%s, duration=%s\n", ttl, checkInterval)
		dnsCache = storage.NewDnsCacheStorage(ttl, checkInterval)
	}
}
