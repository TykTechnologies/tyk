package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
)

// Benchmarks for the request-path half of upstream DNS discovery. It runs on
// every proxied request for an API with the feature on, so it must not
// resolve, must not take a lock, and must not rebuild the target list while
// membership is unchanged. Refresh cost is measured in internal/dnsdiscovery.

// benchGateway wires a fixed answer into a gateway's scheduler in place, since
// the scheduler holds a mutex and must not be copied.
func benchGateway(addrsPerHost int) *Gateway {
	addrs := benchAddrs(addrsPerHost)

	gw := &Gateway{}
	gw.ctx = context.Background()
	gw.upstreamDNS.Lookup = func(_ context.Context, _ string) ([]string, error) {
		return addrs, nil
	}
	gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }
	return gw
}

// benchSpec builds a spec subscribed to host, with its first address set already
// published.
func benchSpec(b *testing.B, gw *Gateway, apiID, target string) *APISpec {
	b.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = apiID
	spec.Proxy.TargetURL = target
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.DNSDiscovery.RefreshInterval = 3600

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	gw.setupUpstreamDNSDiscovery(spec, logger)
	if spec.dnsDiscovery == nil {
		b.Fatalf("%s got no plan for %q", apiID, target)
	}

	// The scheduler goroutine does the first lookup in production. Resolving
	// here keeps the measured iterations to cache hits.
	gw.upstreamDNS.Refresh(context.Background())
	return spec
}

// BenchmarkUpstreamDNS_RequestPath is the steady state, an atomic load and a
// comparison, which is all but a handful of requests between refreshes.
func BenchmarkUpstreamDNS_RequestPath(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw := benchGateway(pods)
			spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")

			// Prime the rendered list so the loop measures cache hits.
			if _, err := gw.urlFromDNS(spec); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				list, err := gw.urlFromDNS(spec)
				if err != nil || list == nil {
					b.Fatalf("urlFromDNS: %v", err)
				}
			}
		})
	}
}

// BenchmarkUpstreamDNS_RequestPathParallel runs the same read from several
// goroutines, since the published set is shared and the point of the atomic
// pointer is that concurrent requests do not contend.
func BenchmarkUpstreamDNS_RequestPathParallel(b *testing.B) {
	gw := benchGateway(10)
	spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")

	if _, err := gw.urlFromDNS(spec); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := gw.urlFromDNS(spec); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkUpstreamDNS_RequestPathRebuild is the cost when a refresh has moved
// the address set. It is paid per membership change rather than per request,
// but by every request in flight when the version moves: several race to
// rebuild and the last store wins. Bounded by request concurrency.
func BenchmarkUpstreamDNS_RequestPathRebuild(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw := benchGateway(pods)
			spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")
			plan := spec.dnsDiscovery

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Drop the cache so every iteration rebuilds.
				plan.rendered.Store(nil)
				if _, err := gw.urlFromDNS(spec); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUpstreamDNS_RequestPathDisabled is the control. An API without the
// feature must not pay for it existing.
func BenchmarkUpstreamDNS_RequestPathDisabled(b *testing.B) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "h2c://svc:9002"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if upstreamDNSDiscoveryEnabled(spec) {
			b.Fatal("discovery reported enabled for an API that did not configure it")
		}
	}
}

// BenchmarkUpstreamDNS_BuildTarget isolates rendering one address into a target
// URL, which runs once per address on every membership change.
func BenchmarkUpstreamDNS_BuildTarget(b *testing.B) {
	target, err := url.Parse("h2c://my-grpc-svc:9002/base")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if buildUpstreamTarget(target, "10.0.0.1", "9002") == "" {
			b.Fatal("empty target")
		}
	}
}

// BenchmarkUpstreamDNS_Director is the whole per-request cost rather than the
// target list read on its own: picking a target, rendering it through
// EnsureTransport, and setting the URL and the authority. The discovery arms
// are read against the static one, the same Director working from a configured
// list.
func BenchmarkUpstreamDNS_Director(b *testing.B) {
	newDirector := func(b *testing.B, configure func(*Gateway) *APISpec) func(*http.Request) {
		b.Helper()

		gw := &Gateway{}
		gw.ctx = context.Background()
		gw.SetConfig(config.Config{}, true)

		spec := configure(gw)

		target, err := url.Parse(spec.Proxy.TargetURL)
		if err != nil {
			b.Fatalf("parse target: %v", err)
		}

		logger := logrus.NewEntry(logrus.New())
		logger.Logger.SetLevel(logrus.PanicLevel)

		return gw.TykNewSingleHostReverseProxy(target, spec, logger).Director
	}

	run := func(b *testing.B, director func(*http.Request)) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			director(httptest.NewRequest(http.MethodPost, "http://gateway/greet", nil))
		}
	}

	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("discovery/pods=%d", pods), func(b *testing.B) {
			addrs := benchAddrs(pods)
			director := newDirector(b, func(gw *Gateway) *APISpec {
				gw.upstreamDNS.Lookup = func(_ context.Context, _ string) ([]string, error) { return addrs, nil }
				gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }

				spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")
				return spec
			})
			run(b, director)
		})
	}

	b.Run("static target list/pods=10", func(b *testing.B) {
		director := newDirector(b, func(gw *Gateway) *APISpec {
			targets := make([]string, 0, 10)
			for _, addr := range benchAddrs(10) {
				targets = append(targets, "h2c://"+addr+":9002")
			}

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = "h2c://svc:9002"
			spec.Proxy.EnableLoadBalancing = true
			spec.Proxy.Targets = targets
			spec.Proxy.StructuredTargetList = apidef.NewHostListFromList(targets)
			return spec
		})
		run(b, director)
	})

	b.Run("no target list at all", func(b *testing.B) {
		director := newDirector(b, func(gw *Gateway) *APISpec {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = "http://svc:8080"
			return spec
		})
		run(b, director)
	})
}

// BenchmarkUpstreamConnRegistry_Track measures what every dial to a discovered
// backend pays, and what every close pays to come off the books. One mutex
// covers the whole registry, so the parallel case is the one that matters.
func BenchmarkUpstreamConnRegistry_Track(b *testing.B) {
	addrs := benchAddrs(10)

	b.Run("serial", func(b *testing.B) {
		registry := newUpstreamConnRegistry()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			addr := net.JoinHostPort(addrs[i%len(addrs)], "9002")
			tracked := registry.track(addr, benchNopConn{})
			_ = tracked.Close()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		registry := newUpstreamConnRegistry()

		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				addr := net.JoinHostPort(addrs[i%len(addrs)], "9002")
				tracked := registry.track(addr, benchNopConn{})
				_ = tracked.Close()
				i++
			}
		})
	})
}

// BenchmarkUpstreamDNS_MembershipChange measures what a refresh that moved the
// address set costs the subscriber: two set differences and a drain or cancel
// per address that moved. Paid per refresh interval during a rolling update,
// once per API on the name.
func BenchmarkUpstreamDNS_MembershipChange(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			addrs := benchAddrs(pods)

			plan := &dnsDiscoveryPlan{
				port:  "9002",
				drain: 30 * time.Second,
				conns: newUpstreamConnRegistry(),
			}

			// One pod leaves and comes back, as in a rolling update. Both
			// directions of the diff are non-empty, which is the worst case.
			full := &dnsdiscovery.State{Version: 1, Addrs: addrs}
			short := &dnsdiscovery.State{Version: 2, Addrs: addrs[1:]}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan.onAddressSet(short)
				plan.onAddressSet(full)
			}
		})
	}
}

// benchAddrs builds n distinct backend addresses.
func benchAddrs(n int) []string {
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}
	return addrs
}

// benchNopConn stands in for a dialled connection, so the registry benchmarks
// measure the bookkeeping rather than the kernel.
type benchNopConn struct{ net.Conn }

func (benchNopConn) Close() error { return nil }
