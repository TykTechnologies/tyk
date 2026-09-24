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
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

func benchGateway(b *testing.B, addrsPerHost int) *Gateway {
	b.Helper()
	addrs := benchAddrs(addrsPerHost)

	gw := &Gateway{}
	gw.ctx = b.Context()
	gw.upstreamDNS.Lookup = func(_ context.Context, _ string) ([]string, error) {
		return addrs, nil
	}
	gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }
	return gw
}

func benchSpec(b *testing.B, gw *Gateway, apiID, target string) *APISpec {
	b.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = apiID
	spec.Proxy.TargetURL = target
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.DNSDiscovery.RefreshInterval = tyktime.ReadableDuration(time.Hour)

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	gw.setupUpstreamDNSDiscovery(spec, logger)
	plan := spec.dnsDiscovery.Load()
	if plan == nil {
		b.Fatalf("%s got no plan for %q", apiID, target)
	}
	b.Cleanup(plan.sub.Release)

	// Refresh can skip a lookup already claimed by the background loop.
	// Warm waits for that lookup so we never measure the unresolved path.
	ctx, cancel := context.WithTimeout(gw.ctx, 5*time.Second)
	defer cancel()
	if unresolved := gw.upstreamDNS.Warm(ctx); len(unresolved) != 0 {
		b.Fatalf("unresolved benchmark hosts: %v", unresolved)
	}
	if !plan.sub.State().Usable() {
		b.Fatal("benchmark hostname has no usable addresses")
	}
	if list, _ := gw.urlFromDNS(spec); list == nil || list.Len() == 0 {
		b.Fatal("benchmark hostname has no rendered targets")
	}
	return spec
}

func BenchmarkUpstreamDNS_RequestPath(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw := benchGateway(b, pods)
			spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if list, _ := gw.urlFromDNS(spec); list == nil {
					b.Fatal("no target list")
				}
			}
		})
	}
}

func BenchmarkUpstreamDNS_RequestPathParallel(b *testing.B) {
	gw := benchGateway(b, 10)
	spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			gw.urlFromDNS(spec)
		}
	})
}

func BenchmarkUpstreamDNS_RequestPathRebuild(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw := benchGateway(b, pods)
			spec := benchSpec(b, gw, "api-1", "h2c://svc:9002")
			plan := spec.dnsDiscovery.Load()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan.rendered.Store(nil)
				gw.urlFromDNS(spec)
			}
		})
	}
}

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

func BenchmarkUpstreamDNS_Director(b *testing.B) {
	newDirector := func(b *testing.B, configure func(*Gateway) *APISpec) func(*http.Request) {
		b.Helper()

		gw := &Gateway{}
		gw.ctx = b.Context()
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
		req := httptest.NewRequest(http.MethodPost, "http://gateway/greet", nil)
		req.Header.Set("User-Agent", "benchmark")
		original, originalURL := *req, *req.URL

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Reset routing and context mutations without timing request creation.
			*req = original
			*req.URL = originalURL
			director(req)
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
		director := newDirector(b, func(_ *Gateway) *APISpec {
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
		director := newDirector(b, func(_ *Gateway) *APISpec {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = "http://svc:8080"
			return spec
		})
		run(b, director)
	})
}

func BenchmarkUpstreamConnRegistry_Track(b *testing.B) {
	addrs := benchAddrs(10)

	b.Run("serial", func(b *testing.B) {
		registry := newUpstreamConnRegistry(nil)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			addr := net.JoinHostPort(addrs[i%len(addrs)], "9002")
			tracked, _ := registry.track(addr, benchNopConn{}, upstreamSelection{})
			_ = tracked.Close()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		registry := newUpstreamConnRegistry(nil)

		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				addr := net.JoinHostPort(addrs[i%len(addrs)], "9002")
				tracked, _ := registry.track(addr, benchNopConn{}, upstreamSelection{})
				_ = tracked.Close()
				i++
			}
		})
	})
}

func BenchmarkUpstreamDNS_MembershipChange(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			addrs := benchAddrs(pods)

			plan := &dnsDiscoveryPlan{
				port:       "9002",
				drain:      30 * time.Second,
				conns:      newUpstreamConnRegistry(nil),
				generation: 1,
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan.onAddressSet(&dnsdiscovery.State{Version: uint64(2*i + 1), Addrs: addrs[1:]})
				plan.onAddressSet(&dnsdiscovery.State{Version: uint64(2*i + 2), Addrs: addrs})
			}
		})
	}
}

func benchAddrs(n int) []string {
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}
	return addrs
}

type benchNopConn struct{ net.Conn }

func (benchNopConn) Close() error { return nil }

var benchContextDepths = []int{0, 8, 24}

func deepContextRequest(depth int) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://gateway/greet", nil)
	ctx := req.Context()
	for i := 0; i < depth; i++ {
		ctx = context.WithValue(ctx, ctxKey(i), i)
	}
	return req.WithContext(ctx)
}

func benchSchemeMark(b *testing.B) {
	for _, depth := range benchContextDepths {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			req := deepContextRequest(depth)
			original := *req

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Each operation starts at the advertised context depth.
				*req = original
				markUpstream(req, upstreamMark{h2c: true, discovered: true})
			}
		})
	}
}

func benchSchemeRead(b *testing.B) {
	for _, depth := range benchContextDepths {
		b.Run(fmt.Sprintf("depth=%d/marked", depth), func(b *testing.B) {
			req := deepContextRequest(depth)
			markUpstream(req, upstreamMark{h2c: true, discovered: true})

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, marked := upstreamMarkOf(req); !marked {
					b.Fatal("mark not found")
				}
			}
		})

		b.Run(fmt.Sprintf("depth=%d/absent", depth), func(b *testing.B) {
			req := deepContextRequest(depth)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, marked := upstreamMarkOf(req); marked {
					b.Fatal("unexpected mark")
				}
			}
		})
	}
}

func benchSchemeClassify(b *testing.B) {
	for _, targets := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("targets=%d", targets), func(b *testing.B) {
			list := make([]string, 0, targets)
			for i := 0; i < targets; i++ {
				list = append(list, fmt.Sprintf("h2c://10.0.0.%d:9002", i+1))
			}

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.Proxy.TargetURL = "h2c://svc:9002"
			spec.Proxy.EnableLoadBalancing = true
			spec.Proxy.Targets = list

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				upstreamSchemes(spec)
			}
		})
	}
}

func BenchmarkUpstreamSchemeSelection(b *testing.B) {
	b.Run("mark", benchSchemeMark)
	b.Run("read", benchSchemeRead)
	b.Run("classify targets", benchSchemeClassify)
}

type ctxKey int
