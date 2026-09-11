package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
)

// TestUpstreamDNSDiscovery_SkipsTLSUpstreams pins the scheme guard.
//
// Sending a request to a pod address makes the transport dial an IP literal,
// and Go derives SNI and certificate verification from the URL host whenever
// tls.Config.ServerName is unset, which it always is here. A service
// certificate issued for the service name, with no IP SAN, then fails to
// verify, so every request to that API breaks. Verified out of band: dialling
// one listener by name verifies and by IP fails with "cannot validate
// certificate for <ip> because it doesn't contain any IP SANs".
func TestUpstreamDNSDiscovery_SkipsTLSUpstreams(t *testing.T) {
	cases := []struct {
		scheme  string
		wantTLS bool
	}{
		{"h2c", false},
		{"http", false},
		{"ws", false},
		{"https", true},
		{"HTTPS", true},
		{"wss", true},
		{"tls", true},
	}

	for _, tc := range cases {
		if got := tlsUpstreamScheme(tc.scheme); got != tc.wantTLS {
			t.Errorf("tlsUpstreamScheme(%q) = %v, want %v", tc.scheme, got, tc.wantTLS)
		}
	}
}

// TestSplitUpstreamHostPort covers the default ports, which have to be supplied
// explicitly because resolution answers with bare addresses and no port.
func TestSplitUpstreamHostPort(t *testing.T) {
	cases := []struct {
		raw        string
		host, port string
	}{
		{"h2c://svc:9002", "svc", "9002"},
		{"h2c://svc", "svc", "80"},
		{"http://svc", "svc", "80"},
		{"https://svc", "svc", "443"},
		{"http://svc:8080/base", "svc", "8080"},
	}

	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		host, port := splitUpstreamHostPort(u)
		if host != tc.host || port != tc.port {
			t.Errorf("splitUpstreamHostPort(%q) = (%q, %q), want (%q, %q)",
				tc.raw, host, port, tc.host, tc.port)
		}
	}
}

// TestResolvableHost checks what is worth resolving. An IP literal resolves to
// itself forever, and localhost is not a Service.
func TestResolvableHost(t *testing.T) {
	cases := map[string]bool{
		"upstream":                 true,
		"svc.ns.svc.cluster.local": true,
		"10.0.0.1":                 false,
		"::1":                      false,
		"localhost":                false,
		"LOCALHOST":                false,
		"":                         false,
	}

	for host, want := range cases {
		if got := resolvableHost(host); got != want {
			t.Errorf("resolvableHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestBuildUpstreamTarget checks that the scheme survives.
//
// This is the point of the EnsureTransport change: the h2c transport is chosen
// from the request scheme after the Director has run, so an entry written as
// http:// here would reach a gRPC upstream over HTTP/1.1.
func TestBuildUpstreamTarget(t *testing.T) {
	cases := []struct {
		raw, addr, port, want string
	}{
		{"h2c://svc:9002", "10.0.0.1", "9002", "h2c://10.0.0.1:9002"},
		{"http://svc:8080", "10.0.0.2", "8080", "http://10.0.0.2:8080"},
		{"h2c://svc:9002/base", "10.0.0.3", "9002", "h2c://10.0.0.3:9002/base"},
		{"h2c://svc:9002/", "10.0.0.4", "9002", "h2c://10.0.0.4:9002"},
	}

	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if got := buildUpstreamTarget(u, tc.addr, tc.port); got != tc.want {
			t.Errorf("buildUpstreamTarget(%q, %q) = %q, want %q", tc.raw, tc.addr, got, tc.want)
		}
	}
}

// TestResolveDNSDiscoveryInterval pins the default and the floor.
func TestResolveDNSDiscoveryInterval(t *testing.T) {
	cases := map[int64]time.Duration{
		0:  time.Duration(dnsDiscoveryDefaultInterval) * time.Second,
		-1: time.Duration(dnsDiscoveryDefaultInterval) * time.Second,
		1:  time.Duration(dnsDiscoveryMinInterval) * time.Second,
		4:  time.Duration(dnsDiscoveryMinInterval) * time.Second,
		5:  5 * time.Second,
		60: 60 * time.Second,
	}

	for in, want := range cases {
		if got := resolveDNSDiscoveryInterval(in); got != want {
			t.Errorf("resolveDNSDiscoveryInterval(%d) = %s, want %s", in, got, want)
		}
	}
}

// TestPlanUpstreamDNSDiscovery_Declines pins the cases in which an API should
// not have its target list sourced from DNS.
//
// The load balancing case is the one worth arguing about. DNS discovery is a
// source, and enable_load_balancing is the policy that distributes what a
// source produces, so with the policy off every request would still reach one
// address and enabling discovery would change nothing a customer can observe.
// Refusing it says so rather than appearing to work.
func TestPlanUpstreamDNSDiscovery_Declines(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	cases := []struct {
		name        string
		targetURL   string
		enabled     bool
		loadBalance bool
	}{
		{"setting disabled", "h2c://svc:9002", false, true},
		{"load balancing off", "h2c://svc:9002", true, false},
		{"tls upstream", "https://svc:9002", true, true},
		{"ip literal upstream", "h2c://10.0.0.5:9002", true, true},
		{"localhost upstream", "h2c://localhost:9002", true, true},
		{"empty target", "", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = tc.targetURL
			spec.Proxy.EnableLoadBalancing = tc.loadBalance
			spec.Proxy.DNSDiscovery.Enabled = tc.enabled

			if plan := planUpstreamDNSDiscovery(spec, logger); plan != nil {
				t.Fatalf("planned DNS discovery for %q, expected none", tc.targetURL)
			}
		})
	}
}

// TestPlanUpstreamDNSDiscovery_Accepts is the control for the test above.
// Without it, a plan function that declined everything would pass.
func TestPlanUpstreamDNSDiscovery_Accepts(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "h2c://svc:9002"
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.DNSDiscovery.RefreshInterval = 10

	plan := planUpstreamDNSDiscovery(spec, logger)
	if plan == nil {
		t.Fatal("declined a resolvable cleartext upstream with load balancing on")
	}
	if plan.host != "svc" || plan.port != "9002" {
		t.Fatalf("plan resolved to %s:%s, want svc:9002", plan.host, plan.port)
	}
	if plan.interval != 10*time.Second {
		t.Fatalf("plan interval is %s, want 10s", plan.interval)
	}
}

// stubResolver is a scheduler lookup that answers from a mutable map and counts
// calls per hostname.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	calls   map[string]int
}

func newStubResolver() *stubResolver {
	return &stubResolver{
		answers: map[string][]string{},
		errs:    map[string]error{},
		calls:   map[string]int{},
	}
}

func (r *stubResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
	delete(r.errs, host)
}

func (r *stubResolver) fail(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[host] = err
}

// failNotFound makes the host answer authoritatively that it does not exist,
// which the scheduler treats differently from a resolver it cannot reach.
func (r *stubResolver) failNotFound(host string) {
	r.fail(host, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true})
}

func (r *stubResolver) callsFor(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

func (r *stubResolver) lookup(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls[host]++
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.answers[host], nil
}

// subscribeAndRefresh subscribes and performs the first resolution inline.
//
// Production leaves that first lookup to the scheduler goroutine, so that a
// slow resolver cannot delay API load. A test that suppresses the loop has to
// do it itself.
func subscribeAndRefresh(s *upstreamDNSScheduler, ctx context.Context, apiID string, plan *dnsDiscoveryPlan) *dnsDiscoveryEntry {
	entry := s.subscribe(ctx, apiID, plan)
	s.refresh(ctx, entry)
	return entry
}

// newTestScheduler builds a scheduler that never starts its own goroutine, so
// tests drive refreshes explicitly and nothing races with the assertions.
func newTestScheduler(resolver *stubResolver) *upstreamDNSScheduler {
	s := &upstreamDNSScheduler{}
	configureTestScheduler(s, resolver)
	s.running = true // suppress the background loop
	return s
}

// configureTestScheduler prepares a scheduler in place. The scheduler holds a
// mutex and an atomic counter, so it must never be copied by value.
func configureTestScheduler(s *upstreamDNSScheduler, resolver *stubResolver) {
	s.entries = map[string]*dnsDiscoveryEntry{}
	s.subscriptions = map[string]*dnsSubscription{}
	s.wake = make(chan struct{}, 1)
	s.lookup = resolver.lookup
	s.jitter = func(d time.Duration) time.Duration { return d }
}

// refreshAndReportDelay refreshes one entry and returns how far ahead the next
// refresh was scheduled, so a test can observe the backoff.
func (s *upstreamDNSScheduler) refreshAndReportDelay(ctx context.Context, entry *dnsDiscoveryEntry) time.Duration {
	before := time.Now()
	s.refresh(ctx, entry)

	s.mu.Lock()
	defer s.mu.Unlock()
	return entry.nextDue.Sub(before)
}

// TestScheduler_OneLookupPerHostname is the claim the whole shape rests on:
// query volume follows the number of distinct upstream hostnames, not the
// number of APIs.
//
// This is what the systems in the same category all do. A poller per API would
// make ten lookups here where two are needed.
func TestScheduler_OneLookupPerHostname(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1", "10.0.0.2")
	resolver.set("svc-b", "10.0.1.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		scheduler.subscribe(ctx, fmt.Sprintf("api-a-%d", i), planFor(t, "h2c://svc-a:9002", 30*time.Second))
	}
	for i := 0; i < 2; i++ {
		scheduler.subscribe(ctx, fmt.Sprintf("api-b-%d", i), planFor(t, "h2c://svc-b:9002", 30*time.Second))
	}

	// Ten subscriptions, and the scheduler has two hostnames to resolve.
	for _, entry := range scheduler.entries {
		scheduler.refresh(ctx, entry)
	}

	if got := resolver.callsFor("svc-a"); got != 1 {
		t.Errorf("svc-a was resolved %d times for 8 subscribing APIs, want 1", got)
	}
	if got := resolver.callsFor("svc-b"); got != 1 {
		t.Errorf("svc-b was resolved %d times for 2 subscribing APIs, want 1", got)
	}

	// A second cycle is also one lookup per hostname.
	for _, entry := range scheduler.entries {
		scheduler.refresh(ctx, entry)
	}
	if got := resolver.callsFor("svc-a"); got != 2 {
		t.Errorf("svc-a was resolved %d times after two cycles, want 2", got)
	}

	if len(scheduler.entries) != 2 {
		t.Errorf("scheduler holds %d entries for 10 APIs on 2 hostnames, want 2", len(scheduler.entries))
	}
}

// TestScheduler_ReleaseDropsEntryWhenLastAPILeaves covers the reference
// counting. An entry shared by two APIs has to survive one of them going away,
// and disappear when the second does.
func TestScheduler_ReleaseDropsEntryWhenLastAPILeaves(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	scheduler.subscribe(ctx, "api-1", planFor(t, "h2c://svc:9002", 30*time.Second))
	scheduler.subscribe(ctx, "api-2", planFor(t, "h2c://svc:9002", 30*time.Second))

	scheduler.releaseAPI("api-1")
	if len(scheduler.entries) != 1 {
		t.Fatalf("entry dropped while api-2 still wants it")
	}

	scheduler.releaseAPI("api-2")
	if len(scheduler.entries) != 0 {
		t.Fatalf("entry survived the last API leaving: %d entries", len(scheduler.entries))
	}

	// Releasing twice must not underflow the count or panic.
	scheduler.releaseAPI("api-2")
}

// TestScheduler_RepointingAnAPIMovesItsSubscription covers a reload that
// changes an API's upstream. The old hostname has to stop being refreshed when
// nothing else points at it.
func TestScheduler_RepointingAnAPIMovesItsSubscription(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("old", "10.0.0.1")
	resolver.set("new", "10.0.1.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	scheduler.subscribe(ctx, "api-1", planFor(t, "h2c://old:9002", 30*time.Second))
	scheduler.subscribe(ctx, "api-1", planFor(t, "h2c://new:9002", 30*time.Second))

	if _, ok := scheduler.entries["old"]; ok {
		t.Error("the previous hostname is still being refreshed after the API was repointed")
	}
	entry, ok := scheduler.entries["new"]
	if !ok {
		t.Fatal("the new hostname was not subscribed")
	}
	if entry.refs != 1 {
		t.Errorf("new entry has %d references, want 1", entry.refs)
	}
}

// TestScheduler_SharedHostnameTakesShortestInterval pins what happens when two
// APIs share an upstream but ask for different refresh rates. They share one
// refresh, so the most eager request has to win or that API silently gets a
// slower one than it configured.
func TestScheduler_SharedHostnameTakesShortestInterval(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	scheduler.subscribe(ctx, "api-slow", planFor(t, "h2c://svc:9002", 60*time.Second))
	scheduler.subscribe(ctx, "api-fast", planFor(t, "h2c://svc:9002", 5*time.Second))

	if got := scheduler.entries["svc"].interval; got != 5*time.Second {
		t.Errorf("shared entry refreshes every %s, want the shortest requested 5s", got)
	}
}

// TestScheduler_FailedLookupKeepsLastGoodAndBacksOff covers the first of the
// two absence cases, and it is the one every comparable system agrees on. DNS
// being unreachable says nothing about whether the pods are still there, so
// discarding a working address set would turn a resolver outage into an API
// outage.
func TestScheduler_FailedLookupKeepsLastGoodAndBacksOff(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	entry := subscribeAndRefresh(scheduler, ctx, "api-1", planFor(t, "h2c://svc:9002", 10*time.Second))
	before := entry.addresses()
	if before == nil || len(before.addrs) != 2 {
		t.Fatalf("first resolution did not publish two addresses: %+v", before)
	}

	resolver.fail("svc", errors.New("servfail"))

	firstBackoff := scheduler.refreshAndReportDelay(ctx, entry)
	after := entry.addresses()
	if after == nil || len(after.addrs) != 2 {
		t.Fatalf("a failed lookup discarded the last good set: %+v", after)
	}
	if after.version != before.version {
		t.Error("a failed lookup bumped the published version, which makes every API rebuild for nothing")
	}

	secondBackoff := scheduler.refreshAndReportDelay(ctx, entry)
	if secondBackoff <= firstBackoff {
		t.Errorf("consecutive failures did not back off: %s then %s", firstBackoff, secondBackoff)
	}

	// Recovery clears the backoff.
	resolver.set("svc", "10.0.0.1", "10.0.0.2", "10.0.0.3")
	scheduler.refresh(ctx, entry)
	if entry.failures != 0 {
		t.Errorf("failure count is %d after a successful lookup, want 0", entry.failures)
	}
	if got := entry.addresses(); got == nil || len(got.addrs) != 3 {
		t.Fatalf("recovery did not publish the new set: %+v", got)
	}
}

// TestScheduler_EmptyAnswerPublishesConfiguredName covers the second absence
// case, which is deliberately not treated like the first.
//
// A successful answer with no records is information: the Service has no ready
// endpoints. Envoy's STRICT_DNS drops the hosts outright there. Publishing the
// configured hostname instead keeps the API on the behaviour it would have had
// without the feature, rather than an empty target list that routes every
// request to the no-healthy-upstreams sink.
func TestScheduler_EmptyAnswerPublishesConfiguredName(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	entry := subscribeAndRefresh(scheduler, ctx, "api-1", planFor(t, "h2c://svc:9002", 10*time.Second))

	resolver.set("svc") // resolves, to nothing
	scheduler.refresh(ctx, entry)

	got := entry.addresses()
	if got == nil {
		t.Fatal("nothing published after an empty answer")
	}
	if len(got.addrs) != 1 || got.addrs[0] != "svc" {
		t.Fatalf("published %v after an empty answer, want the configured name [svc]", got.addrs)
	}
}

// TestScheduler_UnchangedAnswerDoesNotBumpVersion is what keeps the request
// path cheap. CoreDNS shuffles its answers by default, so without sorting and
// comparing, every refresh would look like a membership change and every API
// would rebuild its target list.
func TestScheduler_UnchangedAnswerDoesNotBumpVersion(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.2", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	entry := subscribeAndRefresh(scheduler, ctx, "api-1", planFor(t, "h2c://svc:9002", 10*time.Second))
	first := entry.addresses()

	// Same addresses, different order, as a shuffling resolver returns.
	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	scheduler.refresh(ctx, entry)

	second := entry.addresses()
	if second.version != first.version {
		t.Errorf("a reordered but unchanged answer bumped the version from %d to %d",
			first.version, second.version)
	}
	if second.addrs[0] != "10.0.0.1" {
		t.Errorf("published set is not sorted: %v", second.addrs)
	}
}

// newPlannedSpec builds a spec subscribed to host on the given scheduler.
func newPlannedSpec(t *testing.T, scheduler *upstreamDNSScheduler, apiID, target string) *APISpec {
	t.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = apiID
	spec.Proxy.TargetURL = target
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true

	plan := planUpstreamDNSDiscovery(spec, logrus.NewEntry(logrus.New()))
	if plan == nil {
		t.Fatalf("%s did not get a plan for %q", apiID, target)
	}
	plan.entry = scheduler.subscribe(context.Background(), apiID, plan)
	spec.dnsDiscovery = plan
	return spec
}

// TestUrlFromDNS_RendersEachAPIsOwnTargets covers the split between the shared
// part and the per-API part: the address set is shared, and each API renders it
// with its own scheme, port and path.
func TestUrlFromDNS_RendersEachAPIsOwnTargets(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.2", "10.0.0.1")

	gw := &Gateway{}
	scheduler := &gw.upstreamDNS
	configureTestScheduler(scheduler, resolver)
	scheduler.running = true

	first := newPlannedSpec(t, scheduler, "api-1", "h2c://svc:9002")
	second := newPlannedSpec(t, scheduler, "api-2", "h2c://svc:9002/v2")

	// Two APIs, one hostname, one refresh between them.
	scheduler.refresh(context.Background(), first.dnsDiscovery.entry)

	firstList, err := gw.urlFromDNS(first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	secondList, err := gw.urlFromDNS(second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if firstList.Len() != 2 || secondList.Len() != 2 {
		t.Fatalf("target lists hold %d and %d entries, want 2 each", firstList.Len(), secondList.Len())
	}

	firstEntry, _ := firstList.GetIndex(0)
	if want := "h2c://10.0.0.1:9002"; firstEntry != want {
		t.Errorf("first target is %q, want %q (addresses should be sorted)", firstEntry, want)
	}
	secondEntry, _ := secondList.GetIndex(0)
	if want := "h2c://10.0.0.1:9002/v2"; secondEntry != want {
		t.Errorf("second target is %q, want %q (each API renders its own path)", secondEntry, want)
	}

	if got := resolver.callsFor("svc"); got != 1 {
		t.Errorf("svc was resolved %d times for two APIs, want 1", got)
	}
}

// TestUrlFromDNS_ReusesRenderedListUntilMembershipChanges pins the request-path
// cache. Rebuilding a target list per request would allocate on every proxied
// request for no reason, since membership changes on the order of the refresh
// interval rather than the request rate.
func TestUrlFromDNS_ReusesRenderedListUntilMembershipChanges(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	gw := &Gateway{}
	scheduler := &gw.upstreamDNS
	configureTestScheduler(scheduler, resolver)
	scheduler.running = true

	spec := newPlannedSpec(t, scheduler, "api-1", "h2c://svc:9002")
	scheduler.refresh(context.Background(), spec.dnsDiscovery.entry)

	first, _ := gw.urlFromDNS(spec)
	second, _ := gw.urlFromDNS(spec)
	if first != second {
		t.Error("two calls with unchanged membership built two target lists")
	}

	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	scheduler.refresh(context.Background(), spec.dnsDiscovery.entry)

	third, _ := gw.urlFromDNS(spec)
	if third == second {
		t.Error("the target list was reused after membership changed")
	}
	if third.Len() != 2 {
		t.Errorf("rebuilt list holds %d entries, want 2", third.Len())
	}
}

// TestUrlFromDNS_FallsBackBeforeFirstResolution covers the window between an
// API loading and its first answer arriving. It should behave as it does today
// rather than having no targets.
func TestUrlFromDNS_FallsBackBeforeFirstResolution(t *testing.T) {
	gw := &Gateway{}
	configureTestScheduler(&gw.upstreamDNS, newStubResolver())
	gw.upstreamDNS.running = true

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "h2c://svc:9002"
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.dnsDiscovery = planUpstreamDNSDiscovery(spec, logrus.NewEntry(logrus.New()))
	spec.dnsDiscovery.entry = &dnsDiscoveryEntry{host: "svc"} // nothing published

	list, err := gw.urlFromDNS(spec)
	if err != nil {
		t.Fatalf("urlFromDNS: %v", err)
	}
	if list.Len() != 1 {
		t.Fatalf("list holds %d entries before the first resolution, want 1", list.Len())
	}
	entry, _ := list.GetIndex(0)
	if entry != "h2c://svc:9002" {
		t.Errorf("fell back to %q, want the configured target", entry)
	}
}

// TestScheduler_DiscoversWithoutTraffic is the property that resolving on
// request cannot provide, and the reason the design moved back to a background
// refresh. No request is made here at all.
func TestScheduler_DiscoversWithoutTraffic(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver)
	// Let the real loop run, at an interval short enough to observe.
	scheduler.running = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entry := scheduler.subscribe(ctx, "api-1", planFor(t, "h2c://svc:9002", 20*time.Millisecond))
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if set := entry.addresses(); set != nil && len(set.addrs) == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the scheduler did not pick up the second address without any traffic; published %+v",
		entry.addresses())
}

// TestScheduler_ShortIntervalIsNotStarvedByLongOne pins the scheduling rule
// that a hostname is refreshed on its own interval regardless of what else is
// registered.
//
// The first implementation computed how long to sleep before performing the
// refreshes that were due, so the entries it had just refreshed did not
// contribute their new deadlines. With one hostname on 5 seconds and another on
// 300, the sleep was taken from the 300 and the eager hostname was refreshed
// once every 300 seconds instead. A single-entry test cannot see it.
func TestScheduler_ShortIntervalIsNotStarvedByLongOne(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("fast", "10.0.0.1")
	resolver.set("slow", "10.0.1.1")

	scheduler := newTestScheduler(resolver)
	scheduler.running = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The slow hostname is registered first, so its deadline is the one a
	// naive minimum would pick up.
	scheduler.subscribe(ctx, "api-slow", planFor(t, "h2c://slow:9002", time.Hour))
	scheduler.subscribe(ctx, "api-fast", planFor(t, "h2c://fast:9002", 20*time.Millisecond))

	// One lookup each from the synchronous first resolution.
	before := resolver.callsFor("fast")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resolver.callsFor("fast") >= before+3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the 20ms hostname was refreshed %d times in 5s (want at least %d); "+
		"an hour-long interval on an unrelated hostname is deciding how often it runs",
		resolver.callsFor("fast")-before, 3)
}

// newPlan builds a plan for target with an explicit interval, bypassing the
// configured floor so a test can use a short one. Usable from benchmarks too,
// which is why it takes no testing handle.
func newPlan(target string, interval time.Duration) *dnsDiscoveryPlan {
	u, err := url.Parse(target)
	if err != nil {
		panic("newPlan: " + err.Error())
	}
	host, port := splitUpstreamHostPort(u)
	return &dnsDiscoveryPlan{
		target:   u,
		host:     host,
		port:     port,
		interval: interval,
		fallback: apidef.NewHostListFromList([]string{target}),
	}
}

// planFor is newPlan with a test handle, for readability at call sites.
func planFor(t *testing.T, target string, interval time.Duration) *dnsDiscoveryPlan {
	t.Helper()
	return newPlan(target, interval)
}

// TestScheduler_SubscribeDoesNotResolveInline pins that API load never waits on
// DNS.
//
// The first implementation resolved synchronously inside subscribe, which runs
// on the single-threaded spec loop that gates the router swap, so a resolver
// that timed out delayed every API behind it by the lookup timeout in turn.
// Fifty new hostnames against a sick resolver was fifty serial timeouts.
func TestScheduler_SubscribeDoesNotResolveInline(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	scheduler := newTestScheduler(resolver) // loop suppressed
	entry := scheduler.subscribe(context.Background(), "api-1", planFor(t, "h2c://svc:9002", time.Minute))

	if got := resolver.callsFor("svc"); got != 0 {
		t.Errorf("subscribe performed %d lookups; the scheduler goroutine owns the first one", got)
	}
	if entry.addresses() != nil {
		t.Error("subscribe published an address set, so it must have resolved inline")
	}

	// And the entry is due at once, so the loop picks it up without waiting a
	// whole interval.
	if len(scheduler.dueEntries()) != 1 {
		t.Error("a newly subscribed hostname is not due, so the loop would wait an interval before resolving it")
	}
}

// TestScheduler_NameNotFoundIsAppliedAtOnce covers the authoritative case. A
// name that does not exist is a fact, not a failure to learn one, so there is
// nothing stale worth preserving and the stale TTL does not apply.
func TestScheduler_NameNotFoundIsAppliedAtOnce(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	plan := planFor(t, "h2c://svc:9002", 10*time.Second)
	plan.staleTTL = time.Hour // long enough that a stale bound cannot explain the result
	entry := subscribeAndRefresh(scheduler, ctx, "api-1", plan)

	if got := entry.addresses(); got == nil || len(got.addrs) != 2 {
		t.Fatalf("first resolution published %+v, want two addresses", got)
	}

	resolver.failNotFound("svc")
	scheduler.refresh(ctx, entry)

	got := entry.addresses()
	if got == nil || len(got.addrs) != 1 || got.addrs[0] != "svc" {
		t.Fatalf("published %+v after the name stopped existing, want the configured name [svc]", got)
	}
}

// TestScheduler_StaleTTLBoundsAnUnreachableResolver covers the other half. A
// resolver that cannot be reached says nothing about the pods, so the addresses
// are kept, but not forever: without a bound a deleted upstream would receive
// traffic at dead addresses for the life of the process.
func TestScheduler_StaleTTLBoundsAnUnreachableResolver(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	// Drive the clock, so the bound is tested without sleeping.
	now := time.Now()
	scheduler.now = func() time.Time { return now }

	plan := planFor(t, "h2c://svc:9002", 10*time.Second)
	plan.staleTTL = 5 * time.Minute
	entry := subscribeAndRefresh(scheduler, ctx, "api-1", plan)

	resolver.fail("svc", errors.New("i/o timeout"))

	// Inside the bound, the addresses are kept.
	now = now.Add(time.Minute)
	scheduler.refresh(ctx, entry)
	if got := entry.addresses(); got == nil || len(got.addrs) != 2 {
		t.Fatalf("addresses were dropped one minute into a five minute stale TTL: %+v", got)
	}

	// Past it, the API falls back to its configured target and resolution
	// returns to the dial path.
	now = now.Add(6 * time.Minute)
	scheduler.refresh(ctx, entry)
	got := entry.addresses()
	if got == nil || len(got.addrs) != 1 || got.addrs[0] != "svc" {
		t.Fatalf("published %+v past the stale TTL, want the configured name [svc]", got)
	}
}

// TestScheduler_NegativeStaleTTLNeverGivesUp is the escape hatch for a
// deployment that would rather keep a stale set than fall back.
func TestScheduler_NegativeStaleTTLNeverGivesUp(t *testing.T) {
	if got := resolveDNSDiscoveryStaleTTL(-1); got != 0 {
		t.Fatalf("resolveDNSDiscoveryStaleTTL(-1) = %s, want 0 meaning never", got)
	}
	if got := resolveDNSDiscoveryStaleTTL(0); got != time.Duration(dnsDiscoveryDefaultStaleTTL)*time.Second {
		t.Fatalf("resolveDNSDiscoveryStaleTTL(0) = %s, want the default", got)
	}

	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	scheduler := newTestScheduler(resolver)
	ctx := context.Background()

	now := time.Now()
	scheduler.now = func() time.Time { return now }

	plan := planFor(t, "h2c://svc:9002", 10*time.Second)
	plan.staleTTL = 0 // never
	entry := subscribeAndRefresh(scheduler, ctx, "api-1", plan)

	resolver.fail("svc", errors.New("i/o timeout"))
	now = now.Add(48 * time.Hour)
	scheduler.refresh(ctx, entry)

	if got := entry.addresses(); got == nil || len(got.addrs) != 2 {
		t.Fatalf("addresses were dropped after two days with the bound disabled: %+v", got)
	}
}
