package gateway

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
)

// Benchmarks for upstream DNS discovery.
//
// Two claims are worth measuring, because both were arguments in choosing the
// design and neither is obvious from reading the code.
//
// The request path has to be cheap. Sourcing the target list from DNS happens
// on every proxied request for an API that has it enabled, so it must not
// resolve, must not take a lock, and must not rebuild the target list while
// membership is unchanged. BenchmarkUpstreamDNS_RequestPath measures the steady
// state and BenchmarkUpstreamDNS_RequestPathRebuild the cost when a refresh has
// actually moved the address set, which happens on the order of the refresh
// interval rather than the request rate.
//
// Refresh cost has to follow the number of distinct upstream hostnames rather
// than the number of APIs. That is the whole reason the scheduler is keyed by
// hostname, and BenchmarkUpstreamDNS_RefreshCycle measures it directly by
// holding the API count fixed and varying how many names those APIs share.

// benchScheduler builds a scheduler with a fixed answer per hostname and no
// background goroutine, so a benchmark measures only what it calls.
func benchScheduler(b *testing.B, addrsPerHost int) *upstreamDNSScheduler {
	b.Helper()

	addrs := make([]string, 0, addrsPerHost)
	for i := 0; i < addrsPerHost; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}

	s := &upstreamDNSScheduler{
		entries:       map[string]*dnsDiscoveryEntry{},
		subscriptions: map[string]*dnsSubscription{},
		running:       true, // no background loop during a benchmark
		wake:          make(chan struct{}, 1),
		lookup: func(_ context.Context, _ string) ([]string, error) {
			return addrs, nil
		},
		jitter: func(d time.Duration) time.Duration { return d },
	}
	return s
}

// benchGateway wires a scheduler into a gateway in place, since the scheduler
// holds a mutex and an atomic counter and must not be copied.
func benchGateway(b *testing.B, addrsPerHost int) (*Gateway, *upstreamDNSScheduler) {
	b.Helper()

	template := benchScheduler(b, addrsPerHost)
	gw := &Gateway{}
	s := &gw.upstreamDNS
	s.entries = map[string]*dnsDiscoveryEntry{}
	s.subscriptions = map[string]*dnsSubscription{}
	s.running = true
	s.wake = make(chan struct{}, 1)
	s.lookup = template.lookup
	s.jitter = template.jitter
	return gw, s
}

// benchSpec builds a spec subscribed to host, with its first address set
// already published.
func benchSpec(b *testing.B, scheduler *upstreamDNSScheduler, apiID, target string) *APISpec {
	b.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = apiID
	spec.Proxy.TargetURL = target
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	plan := planUpstreamDNSDiscovery(spec, logger)
	if plan == nil {
		b.Fatalf("%s got no plan for %q", apiID, target)
	}
	plan.entry = scheduler.subscribe(context.Background(), apiID, plan)
	// Production leaves the first lookup to the scheduler goroutine; a
	// benchmark that suppresses the loop resolves it here so the measured
	// iterations are cache hits.
	scheduler.refresh(context.Background(), plan.entry)
	spec.dnsDiscovery = plan
	return spec
}

// BenchmarkUpstreamDNS_RequestPath is the steady state: membership has not
// changed since the last request, which is the case for all but a handful of
// requests between refreshes. It should be an atomic load and a comparison.
func BenchmarkUpstreamDNS_RequestPath(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw, scheduler := benchGateway(b, pods)
			spec := benchSpec(b, scheduler, "api-1", "h2c://svc:9002")

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
	gw, scheduler := benchGateway(b, 10)
	spec := benchSpec(b, scheduler, "api-1", "h2c://svc:9002")

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

// BenchmarkUpstreamDNS_RequestPathRebuild is the cost paid when a refresh has
// changed the address set and the target list has to be built again. It is the
// number to compare the steady state against, and the reason the rendered list
// is cached by version.
//
// Worth reading precisely: the cache means this is paid per membership change
// rather than per request, but it is paid by every request in flight at the
// moment the version moves, not once for the whole gateway. Several will race
// to rebuild and the last store wins. That is bounded by the request
// concurrency and self-corrects on the next request, so it is left as is.
func BenchmarkUpstreamDNS_RequestPathRebuild(b *testing.B) {
	for _, pods := range []int{2, 10, 50} {
		b.Run(fmt.Sprintf("pods=%d", pods), func(b *testing.B) {
			gw, scheduler := benchGateway(b, pods)
			spec := benchSpec(b, scheduler, "api-1", "h2c://svc:9002")
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

// BenchmarkUpstreamDNS_RequestPathDisabled is the control. An API that has not
// enabled DNS discovery must not pay for the feature existing, and the Director
// reaches urlFromDNS only through upstreamDNSDiscoveryEnabled.
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

// BenchmarkUpstreamDNS_RefreshCycle holds the API count at 1000 and varies how
// many distinct hostnames they point at, which is what a real deployment does:
// many APIs, far fewer upstream Services.
//
// One refresh cycle should cost one lookup per hostname, so the measured time
// should track hosts and be flat in APIs. A poller per API would instead cost
// 1000 lookups in every one of these cases.
func BenchmarkUpstreamDNS_RefreshCycle(b *testing.B) {
	const apis = 1000

	for _, hosts := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("apis=%d/hosts=%d", apis, hosts), func(b *testing.B) {
			scheduler := benchScheduler(b, 4)
			ctx := context.Background()

			for i := 0; i < apis; i++ {
				host := fmt.Sprintf("svc-%d", i%hosts)
				scheduler.subscribe(ctx, fmt.Sprintf("api-%d", i), newPlan("h2c://"+host+":9002", 30*time.Second))
			}
			if got := len(scheduler.entries); got != hosts {
				b.Fatalf("scheduler holds %d entries, want %d", got, hosts)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, entry := range scheduler.entries {
					scheduler.refresh(ctx, entry)
				}
			}
			b.StopTimer()

			// Report the lookups a cycle actually costs, which is the claim
			// being made: hostnames, not APIs.
			b.ReportMetric(float64(hosts), "lookups/cycle")
		})
	}
}

// BenchmarkUpstreamDNS_DueEntries measures the scan the scheduler goroutine
// does on each wake to find what is due. It runs once per wake rather than once
// per request or per API, but it is the part that grows with the number of
// distinct hostnames, so it is worth knowing.
func BenchmarkUpstreamDNS_DueEntries(b *testing.B) {
	for _, hosts := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			scheduler := benchScheduler(b, 4)
			ctx := context.Background()

			for i := 0; i < hosts; i++ {
				scheduler.subscribe(ctx, fmt.Sprintf("api-%d", i), newPlan("h2c://"+fmt.Sprintf("svc-%d", i)+":9002", time.Hour))
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				due := scheduler.dueEntries()
				if len(due) != 0 {
					b.Fatalf("%d entries reported due with an hour-long interval", len(due))
				}
			}
		})
	}
}

// BenchmarkUpstreamDNS_Subscribe measures API load, not the request path. It
// matters because every API reload runs it for every API, and a gateway with
// thousands of APIs reloads often.
func BenchmarkUpstreamDNS_Subscribe(b *testing.B) {
	b.Run("new hostname", func(b *testing.B) {
		scheduler := benchScheduler(b, 4)
		ctx := context.Background()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			scheduler.subscribe(ctx, fmt.Sprintf("api-%d", i), newPlan("h2c://"+fmt.Sprintf("svc-%d", i)+":9002", 30*time.Second))
		}
	})

	b.Run("shared hostname", func(b *testing.B) {
		scheduler := benchScheduler(b, 4)
		ctx := context.Background()
		scheduler.subscribe(ctx, "api-seed", newPlan("h2c://"+"svc"+":9002", 30*time.Second))

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			scheduler.subscribe(ctx, fmt.Sprintf("api-%d", i), newPlan("h2c://"+"svc"+":9002", 30*time.Second))
		}
	})
}

// BenchmarkUpstreamDNS_BuildTarget isolates the rendering of one address into a
// target URL, which is the per-API half of the work and the part that runs
// once per address on every membership change.
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
