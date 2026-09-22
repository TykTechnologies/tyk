package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dnscache"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
)

// Dialling a backend means an IP literal, which no service certificate
// covers.
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

func TestSplitUpstreamHostPort(t *testing.T) {
	cases := []struct {
		raw        string
		host, port string
	}{
		{"h2c://svc:9002", "svc", "9002"},
		{"h2c://svc", "svc", "80"},
		{"h2c://svc:9002/base", "svc", "9002"},
	}

	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		host, port := splitUpstreamHostPort(u)
		if host != tc.host || port != tc.port {
			t.Errorf("splitUpstreamHostPort(%q) = %q, %q; want %q, %q", tc.raw, host, port, tc.host, tc.port)
		}
	}
}

// An entry rewritten to http:// would reach a gRPC server over HTTP/1.1.
func TestBuildUpstreamTarget(t *testing.T) {
	cases := []struct {
		raw, addr, port, want string
	}{
		{"h2c://svc:9002", "10.0.0.1", "9002", "h2c://10.0.0.1:9002"},
		{"http://svc:8080", "10.0.0.1", "8080", "http://10.0.0.1:8080"},
		{"h2c://svc:9002/base", "10.0.0.1", "9002", "h2c://10.0.0.1:9002/base"},
		{"h2c://svc:9002/", "10.0.0.1", "9002", "h2c://10.0.0.1:9002"},
		{"h2c://svc:9002", "fd00::1", "9002", "h2c://[fd00::1]:9002"},
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

func testRefreshIntervalResolution(t *testing.T) {
	cases := map[int64]time.Duration{
		0:  time.Duration(dnsDiscoveryDefaultInterval) * time.Second,
		1:  dnsdiscovery.MinInterval,
		4:  dnsdiscovery.MinInterval,
		5:  5 * time.Second,
		60: 60 * time.Second,
	}

	for in, want := range cases {
		got := resolveDNSDiscoveryInterval(apidef.DNSDiscoveryConfig{RefreshInterval: in})
		if got != want {
			t.Errorf("refresh interval for %d = %s, want %s", in, got, want)
		}
	}
}

func testStaleTTLResolution(t *testing.T) {
	unlimited := apidef.DNSDiscoveryConfig{StaleTTL: dnsDiscoveryStaleTTLUnlimited}
	if got := resolveDNSDiscoveryStaleTTL(unlimited); got != dnsdiscovery.StaleTTLUnlimited {
		t.Errorf("stale_ttl -1 = %s, want the unlimited sentinel", got)
	}

	wantDefault := time.Duration(dnsDiscoveryDefaultStaleTTL) * time.Second
	if got := resolveDNSDiscoveryStaleTTL(apidef.DNSDiscoveryConfig{}); got != wantDefault {
		t.Errorf("stale_ttl 0 = %s, want the default %s", got, wantDefault)
	}
	if got := resolveDNSDiscoveryStaleTTL(apidef.DNSDiscoveryConfig{StaleTTL: 30}); got != 30*time.Second {
		t.Errorf("stale_ttl 30 = %s, want 30s", got)
	}
}

func testDrainDeadlineResolution(t *testing.T) {
	disabled := apidef.DNSDiscoveryConfig{DrainDeadline: 60, DrainDisabled: true}
	if got := resolveDNSDiscoveryDrainDeadline(disabled); got != dnsDiscoveryDrainDisabled {
		t.Errorf("drain_disabled = %s, want the disabled sentinel", got)
	}

	wantDefault := time.Duration(dnsDiscoveryDefaultDrainDeadline) * time.Second
	if got := resolveDNSDiscoveryDrainDeadline(apidef.DNSDiscoveryConfig{}); got != wantDefault {
		t.Errorf("drain_deadline 0 = %s, want the default %s", got, wantDefault)
	}
	if got := resolveDNSDiscoveryDrainDeadline(apidef.DNSDiscoveryConfig{DrainDeadline: 60}); got != time.Minute {
		t.Errorf("drain_deadline 60 = %s, want 1m", got)
	}
}

func TestResolveDNSDiscoveryPeriods(t *testing.T) {
	t.Run("refresh interval", testRefreshIntervalResolution)
	t.Run("stale TTL", testStaleTTLResolution)
	t.Run("drain deadline", testDrainDeadlineResolution)
}

// hostAt returns one entry of a host list, failing the test when it is absent.
func hostAt(t *testing.T, list *apidef.HostList, i int) string {
	t.Helper()

	entry, err := list.GetIndex(i)
	if err != nil {
		t.Fatalf("host list index %d: %v", i, err)
	}
	return entry
}

// mustURLFromDNS resolves an API's DNS-sourced target list, failing the test on error.
func mustURLFromDNS(t *testing.T, gw *Gateway, spec *APISpec) *apidef.HostList {
	t.Helper()

	list, err := gw.urlFromDNS(spec)
	if err != nil {
		t.Fatalf("urlFromDNS: %v", err)
	}
	return list
}

// Without load balancing every request still reaches one backend; with
// service discovery there are two sources for one list.
func TestPlanUpstreamDNSDiscovery_Declines(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	cases := []struct {
		name             string
		targetURL        string
		enabled          bool
		loadBalance      bool
		serviceDiscovery bool
	}{
		{name: "setting disabled", targetURL: "h2c://svc:9002", enabled: false, loadBalance: true},
		{name: "load balancing off", targetURL: "h2c://svc:9002", enabled: true, loadBalance: false},
		{name: "service discovery also on", targetURL: "h2c://svc:9002", enabled: true, loadBalance: true, serviceDiscovery: true},
		{name: "tls upstream", targetURL: "https://svc:9002", enabled: true, loadBalance: true},
		{name: "plain http upstream", targetURL: "http://svc:8080", enabled: true, loadBalance: true},
		{name: "websocket upstream", targetURL: "ws://svc:8080", enabled: true, loadBalance: true},
		{name: "ip literal upstream", targetURL: "h2c://10.0.0.5:9002", enabled: true, loadBalance: true},
		{name: "localhost upstream", targetURL: "h2c://localhost:9002", enabled: true, loadBalance: true},
		{name: "empty target", targetURL: "", enabled: true, loadBalance: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = tc.targetURL
			spec.Proxy.EnableLoadBalancing = tc.loadBalance
			spec.Proxy.DNSDiscovery.Enabled = tc.enabled
			spec.Proxy.ServiceDiscovery.UseDiscoveryService = tc.serviceDiscovery

			if planUpstreamDNSDiscovery(spec, logger) != nil {
				t.Fatalf("planned DNS discovery for %q, expected none", tc.targetURL)
			}
		})
	}
}

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
	if plan.conns == nil {
		t.Fatal("no connection registry, so a departed address would never be drained")
	}
}

func TestPlanUpstreamDNSDiscovery_DrainDisabled(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "h2c://svc:9002"
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.DNSDiscovery.DrainDisabled = true

	plan := planUpstreamDNSDiscovery(spec, logrus.NewEntry(logrus.New()))
	if plan == nil {
		t.Fatal("declined an API that only disabled draining")
	}
	if plan.conns != nil {
		t.Error("built a connection registry for an API that disabled draining")
	}
	if upstreamDrainRegistry(&APISpec{APIDefinition: &apidef.APIDefinition{}}) != nil {
		t.Error("an API with no plan reported a registry")
	}
}

// stubResolver moves membership without touching DNS.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
}

func newStubResolver() *stubResolver {
	return &stubResolver{answers: map[string][]string{}, errs: map[string]error{}}
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

func (r *stubResolver) lookup(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.answers[host], nil
}

// The scheduler holds a mutex, so it is wired in place and never copied.
func newDiscoveryGateway(t *testing.T, resolver *stubResolver) *Gateway {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	gw := &Gateway{}
	gw.ctx = ctx
	gw.upstreamDNS.Lookup = resolver.lookup
	gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }
	return gw
}

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock { return &testClock{at: time.Now()} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// Resolves once, so the assertions do not race the scheduler's first pass.
func loadDiscoveredAPI(t *testing.T, gw *Gateway, apiID, target string, configure ...func(*APISpec)) *APISpec {
	t.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = apiID
	spec.Proxy.TargetURL = target
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.DNSDiscovery.RefreshInterval = 3600
	for _, fn := range configure {
		fn(spec)
	}

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	gw.setupUpstreamDNSDiscovery(spec, logger)
	if spec.dnsDiscovery == nil {
		t.Fatalf("%s was not subscribed to %q", apiID, target)
	}

	gw.upstreamDNS.Refresh(context.Background())
	return spec
}

// The address set is shared, the rendering of it is per-API.
func TestUrlFromDNS_RendersEachAPIsOwnTargets(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.2", "10.0.0.1")

	gw := newDiscoveryGateway(t, resolver)

	first := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")
	second := loadDiscoveredAPI(t, gw, "api-2", "h2c://svc:9002/v2")

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

	firstEntry := hostAt(t, firstList, 0)
	if want := "h2c://10.0.0.1:9002"; firstEntry != want {
		t.Errorf("first target is %q, want %q (addresses should be sorted)", firstEntry, want)
	}
	secondEntry := hostAt(t, secondList, 0)
	if want := "h2c://10.0.0.1:9002/v2"; secondEntry != want {
		t.Errorf("second target is %q, want %q (each API renders its own path)", secondEntry, want)
	}
}

// Membership changes on the order of the refresh interval, not the request
// rate, so the rendered list is cached.
func TestUrlFromDNS_ReusesRenderedListUntilMembershipChanges(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	gw := newDiscoveryGateway(t, resolver)
	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

	first := mustURLFromDNS(t, gw, spec)
	second := mustURLFromDNS(t, gw, spec)
	if first != second {
		t.Error("two calls with unchanged membership built two target lists")
	}

	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())

	third := mustURLFromDNS(t, gw, spec)
	if third == second {
		t.Error("the target list was reused after membership changed")
	}
	if third.Len() != 2 {
		t.Errorf("rebuilt list holds %d entries, want 2", third.Len())
	}
}

// Every case with no addresses. They differ in the log, not on the request
// path: each leaves the API where it would be without the feature.
func TestUrlFromDNS_FallsBackToTheConfiguredTarget(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*stubResolver)
	}{
		{"nothing resolved yet", nil},
		{"the name answered with no addresses", func(r *stubResolver) { r.set("svc") }},
		{"the name does not exist", func(r *stubResolver) {
			r.fail("svc", &net.DNSError{Err: "no such host", Name: "svc", IsNotFound: true})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := newStubResolver()
			gw := newDiscoveryGateway(t, resolver)

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.APIID = "api-1"
			spec.Proxy.TargetURL = "h2c://svc:9002"
			spec.Proxy.EnableLoadBalancing = true
			spec.Proxy.DNSDiscovery.Enabled = true

			logger := logrus.NewEntry(logrus.New())
			logger.Logger.SetLevel(logrus.PanicLevel)
			gw.setupUpstreamDNSDiscovery(spec, logger)

			if tc.prepare != nil {
				tc.prepare(resolver)
				gw.upstreamDNS.Refresh(context.Background())
			}

			list, err := gw.urlFromDNS(spec)
			if err != nil {
				t.Fatalf("urlFromDNS: %v", err)
			}
			if list.Len() != 1 {
				t.Fatalf("list holds %d entries, want the configured target only", list.Len())
			}
			if entry := hostAt(t, list, 0); entry != "h2c://svc:9002" {
				t.Errorf("fell back to %q, want the configured target", entry)
			}
		})
	}
}

// A reload replaces a definition rather than unloading it, so nothing else
// releases the subscription.
func TestSetupUpstreamDNSDiscovery_ReleasesOnReconfigure(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	gw := newDiscoveryGateway(t, resolver)
	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	spec.Proxy.DNSDiscovery.Enabled = false
	gw.setupUpstreamDNSDiscovery(spec, logger)

	if spec.dnsDiscovery != nil {
		t.Fatal("the API kept its plan after discovery was switched off")
	}
	if gw.upstreamDNS.Lookups() == 0 {
		t.Skip("nothing was resolved, so there is nothing to assert about release")
	}

	// No entries left, observable as the lookup count staying put.
	before := gw.upstreamDNS.Lookups()
	gw.upstreamDNS.Refresh(context.Background())
	if after := gw.upstreamDNS.Lookups(); after != before {
		t.Errorf("the hostname is still being resolved after the API stopped wanting it: %d lookups", after-before)
	}
}

func TestUpstreamConnRegistry_DrainsDepartedAddresses(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	departing, departingPeer := net.Pipe()
	staying, stayingPeer := net.Pipe()
	defer departingPeer.Close()
	defer stayingPeer.Close()

	trackedDeparting := registry.track("10.0.0.1:9002", departing)
	trackedStaying := registry.track("10.0.0.2:9002", staying)

	if got := registry.countFor("10.0.0.1:9002"); got != 1 {
		t.Fatalf("registry holds %d connections for the dialled address, want 1", got)
	}

	registry.drain("10.0.0.1:9002", time.Millisecond)

	if !closedWithin(t, trackedDeparting, time.Second) {
		t.Fatal("the connection to a departed address was not closed after its drain deadline")
	}
	if closedWithin(t, trackedStaying, 50*time.Millisecond) {
		t.Fatal("draining one address closed a connection to another")
	}
	if got := registry.countFor("10.0.0.1:9002"); got != 0 {
		t.Errorf("registry still holds %d connections for a drained address", got)
	}
}

// A pod keeps serving until its grace period ends, so a request in flight
// has to finish.
func TestUpstreamConnRegistry_DrainIsDeferredNotImmediate(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	conn, peer := net.Pipe()
	defer peer.Close()

	tracked := registry.track("10.0.0.1:9002", conn)
	registry.drain("10.0.0.1:9002", time.Hour)

	if closedWithin(t, tracked, 50*time.Millisecond) {
		t.Fatal("the connection was closed immediately, so an in-flight request would be cut")
	}
}

func TestUpstreamConnRegistry_ReturningAddressCancelsItsDrain(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	conn, peer := net.Pipe()
	defer peer.Close()

	tracked := registry.track("10.0.0.1:9002", conn)
	registry.drain("10.0.0.1:9002", 30*time.Millisecond)
	registry.cancelDrain("10.0.0.1:9002")

	if closedWithin(t, tracked, 200*time.Millisecond) {
		t.Fatal("a cancelled drain still closed the connection")
	}
}

// Unload has already closed the idle connections, so what is left is busy.
func TestUpstreamConnRegistry_CloseRetiresWithoutSevering(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	inFlight, inFlightPeer := net.Pipe()
	defer inFlightPeer.Close()
	defer inFlight.Close()

	tracked := registry.track("10.0.0.1:9002", inFlight)
	registry.drain("10.0.0.2:9002", 10*time.Millisecond)

	registry.close()

	if closedWithin(t, tracked, 200*time.Millisecond) {
		t.Error("unloading the API severed a connection that still had a request on it")
	}
	if got := registry.countFor("10.0.0.1:9002"); got != 0 {
		t.Errorf("a closed registry still tracks %d connections", got)
	}

	// An unloaded API cannot leak through a dialler that outlives it.
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	defer late.Close()

	registry.track("10.0.0.3:9002", late)
	if got := registry.countFor("10.0.0.3:9002"); got != 0 {
		t.Errorf("a closed registry tracked %d new connections", got)
	}
}

// Race regression test. Stop cannot take back a fired timer, so a drain
// expiring as the address is re-dialled has a callback track cannot cancel.
func TestUpstreamConnRegistry_RedialBeatsAnExpiringDrain(t *testing.T) {
	const addr = "10.0.0.1:9002"

	closedFresh := 0
	const attempts = 200

	for i := 0; i < attempts; i++ {
		registry := newUpstreamConnRegistry(nil)

		departing, departingPeer := net.Pipe()
		registry.track(addr, departing)
		registry.drain(addr, 2*time.Millisecond)

		// Re-dial as the deadline arrives, as a returning address does.
		time.Sleep(2 * time.Millisecond)
		fresh, freshPeer := net.Pipe()
		tracked := registry.track(addr, fresh)

		time.Sleep(10 * time.Millisecond)
		if closedWithin(t, tracked, 5*time.Millisecond) {
			closedFresh++
		}

		departingPeer.Close()
		freshPeer.Close()
		registry.close()
	}

	if closedFresh > 0 {
		t.Errorf("%d of %d connections re-dialled as the drain expired were closed by the drain that "+
			"track was supposed to have cancelled", closedFresh, attempts)
	}
}

func TestUpstreamConnRegistry_PoolCloseDeregisters(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	conn, peer := net.Pipe()
	defer peer.Close()

	tracked := registry.track("10.0.0.1:9002", conn)
	if err := tracked.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := registry.countFor("10.0.0.1:9002"); got != 0 {
		t.Errorf("registry holds %d connections after the pool closed one", got)
	}
}

func TestPlanDrainsOnMembershipChange(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	gw := newDiscoveryGateway(t, resolver)
	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.DrainDeadline = 1
	})

	plan := spec.dnsDiscovery
	departing, departingPeer := net.Pipe()
	staying, stayingPeer := net.Pipe()
	defer departingPeer.Close()
	defer stayingPeer.Close()

	trackedDeparting := plan.conns.track("10.0.0.1:9002", departing)
	trackedStaying := plan.conns.track("10.0.0.2:9002", staying)

	resolver.set("svc", "10.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())

	if !closedWithin(t, trackedDeparting, 5*time.Second) {
		t.Fatal("the connection to the departed pod was never closed")
	}
	if closedWithin(t, trackedStaying, 100*time.Millisecond) {
		t.Fatal("the connection to the remaining pod was closed too")
	}
}

func closedWithin(t *testing.T, conn net.Conn, d time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(d)
	for {
		if err := conn.SetWriteDeadline(time.Now().Add(time.Millisecond)); err != nil {
			return true
		}
		_, err := conn.Write([]byte{0})
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUpstreamDNSDiscoveryEnabled(t *testing.T) {
	if upstreamDNSDiscoveryEnabled(nil) {
		t.Error("a nil spec reported discovery enabled")
	}

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	if upstreamDNSDiscoveryEnabled(spec) {
		t.Error("an API with no plan reported discovery enabled")
	}

	spec.dnsDiscovery = &dnsDiscoveryPlan{}
	if !upstreamDNSDiscoveryEnabled(spec) {
		t.Error("an API with a plan reported discovery disabled")
	}
}

// Which source wins, for every combination. The service discovery cases are a
// regression test: adding DNS discovery to a chain of cases that fell through
// replaced the registry list with the static one.
// precedenceRegistry stands in for what a service registry returns.
var precedenceRegistry = []string{"http://registry-1:8080", "http://registry-2:8080"}

func newPrecedenceGateway() *Gateway {
	gw := &Gateway{}
	gw.SetConfig(config.Config{}, true)
	return gw
}

func newPrecedenceSpec(t *testing.T, configure func(*APISpec)) *APISpec {
	t.Helper()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "http://svc:8080"
	configure(spec)
	return spec
}

// primeRegistry stands the registry up from a primed cache, so the test needs
// no HTTP endpoint.
func primeRegistry(gw *Gateway, spec *APISpec) {
	list := apidef.NewHostListFromList(precedenceRegistry)
	gw.ServiceCache = cache.New(30, 15)
	gw.ServiceCache.Set(spec.APIID, list, 30)
	spec.HasRun = true
	spec.LastGoodHostList = list
}

func quietLogger() *logrus.Entry {
	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)
	return logger
}

func testPrecedenceRegistryBeatsStaticList(t *testing.T) {
	gw := newPrecedenceGateway()
	spec := newPrecedenceSpec(t, func(spec *APISpec) {
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.Targets = []string{"http://static:8080"}
		spec.Proxy.StructuredTargetList = apidef.NewHostListFromList(spec.Proxy.Targets)
		spec.Proxy.ServiceDiscovery.UseDiscoveryService = true
	})
	primeRegistry(gw, spec)

	list := gw.upstreamTargetList(spec, quietLogger())
	if list == nil {
		t.Fatal("service discovery produced no target list")
	}
	if got := hostAt(t, list, 0); got != "http://registry-1:8080" {
		t.Fatalf("first target is %q, want the registry's first entry", got)
	}
}

func testPrecedenceRegistryWithoutLoadBalancing(t *testing.T) {
	gw := newPrecedenceGateway()
	// StructuredTargetList is only built with load balancing on, so overwriting
	// leaves a nil list here.
	spec := newPrecedenceSpec(t, func(spec *APISpec) {
		spec.Proxy.ServiceDiscovery.UseDiscoveryService = true
	})
	primeRegistry(gw, spec)

	list := gw.upstreamTargetList(spec, quietLogger())
	if list == nil {
		t.Fatal("service discovery produced no target list with load balancing off")
	}
	if list.Len() != len(precedenceRegistry) {
		t.Fatalf("target list holds %d entries, want the registry's %d", list.Len(), len(precedenceRegistry))
	}
}

func testPrecedenceUnreachableRegistry(t *testing.T) {
	gw := newPrecedenceGateway()
	spec := newPrecedenceSpec(t, func(spec *APISpec) {
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.ServiceDiscovery.UseDiscoveryService = true
		spec.Proxy.ServiceDiscovery.QueryEndpoint = "http://127.0.0.1:1/nothing-here"
	})
	gw.ServiceCache = cache.New(30, 15)

	if list := gw.upstreamTargetList(spec, quietLogger()); list != nil {
		t.Fatalf("a failed registry lookup produced a target list: %v", list.All())
	}
}

func testPrecedenceDNSDiscovery(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	gw := newDiscoveryGateway(t, resolver)
	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

	list := gw.upstreamTargetList(spec, quietLogger())
	if list == nil {
		t.Fatal("DNS discovery produced no target list")
	}
	if got := hostAt(t, list, 0); got != "h2c://10.0.0.1:9002" {
		t.Fatalf("first target is %q, want the resolved pod address", got)
	}
}

func testPrecedenceStaticList(t *testing.T) {
	gw := newPrecedenceGateway()
	spec := newPrecedenceSpec(t, func(spec *APISpec) {
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.Targets = []string{"http://static:8080"}
		spec.Proxy.StructuredTargetList = apidef.NewHostListFromList(spec.Proxy.Targets)
	})

	list := gw.upstreamTargetList(spec, quietLogger())
	if list == nil || list.Len() != 1 {
		t.Fatalf("static target list was not returned: %v", list)
	}
}

func testPrecedenceNoSource(t *testing.T) {
	gw := newPrecedenceGateway()
	spec := newPrecedenceSpec(t, func(*APISpec) {})

	if list := gw.upstreamTargetList(spec, quietLogger()); list != nil {
		t.Fatalf("an API with no source produced a target list: %v", list.All())
	}
}

func TestUpstreamTargetList_SourcePrecedence(t *testing.T) {
	t.Run("service discovery supersedes a static list", testPrecedenceRegistryBeatsStaticList)
	t.Run("service discovery with load balancing off", testPrecedenceRegistryWithoutLoadBalancing)
	t.Run("an unreachable registry falls back to the configured target", testPrecedenceUnreachableRegistry)
	t.Run("DNS discovery when no registry is configured", testPrecedenceDNSDiscovery)
	t.Run("a static list when nothing else is configured", testPrecedenceStaticList)
	t.Run("no source at all", testPrecedenceNoSource)
}

// Dead-peer detection. A backend that dies without closing its side leaves a
// connection the pool believes in, and requests onto it hang.
func TestH2CTransport_HealthChecksDiscoveredUpstreams(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	newTransport := func(t *testing.T, gw *Gateway, spec *APISpec) *TykRoundTripper {
		t.Helper()

		gw.SetConfig(config.Config{}, true)
		gw.dnsCacheManager = dnscache.NewDnsCacheManager(gw.GetConfig().DnsCache.MultipleIPsHandleStrategy)

		proxy := &ReverseProxy{TykAPISpec: spec, Gw: gw, logger: logrus.NewEntry(logrus.New())}
		proxy.logger.Logger.SetLevel(logrus.PanicLevel)

		req := httptest.NewRequest(http.MethodPost, "http://svc:9002/greet", nil)
		outReq := req.Clone(req.Context())
		outReq.URL.Scheme = "h2c"

		rt := proxy.httpTransport(30, httptest.NewRecorder(), req, outReq)
		if rt.h2ctransport == nil {
			t.Fatal("no h2c transport was built for an h2c request")
		}
		return rt
	}

	t.Run("discovered upstream", func(t *testing.T) {
		gw := newDiscoveryGateway(t, resolver)
		spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

		rt := newTransport(t, gw, spec)
		if rt.h2ctransport.ReadIdleTimeout != defaultH2CReadIdleTimeout {
			t.Errorf("ReadIdleTimeout is %s, want %s: a dead backend would go unnoticed",
				rt.h2ctransport.ReadIdleTimeout, defaultH2CReadIdleTimeout)
		}
		if rt.h2ctransport.IdleConnTimeout != defaultH2CIdleConnTimeout {
			t.Errorf("IdleConnTimeout is %s, want %s", rt.h2ctransport.IdleConnTimeout, defaultH2CIdleConnTimeout)
		}
	})

	t.Run("ordinary h2c upstream is unchanged", func(t *testing.T) {
		gw := &Gateway{}

		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.APIID = "api-2"
		spec.Proxy.TargetURL = "h2c://svc:9002"

		rt := newTransport(t, gw, spec)
		if rt.h2ctransport.ReadIdleTimeout != 0 {
			t.Errorf("ReadIdleTimeout is %s for an API that did not opt into discovery, want 0",
				rt.h2ctransport.ReadIdleTimeout)
		}
	})
}

// An unreachable resolver says nothing about whether the backends are
// there.
func TestUrlFromDNS_HoldsTheLastGoodSetWhileTheResolverIsDown(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	gw := newDiscoveryGateway(t, resolver)

	clock := newTestClock()
	gw.upstreamDNS.Now = clock.now

	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.StaleTTL = 60
	})

	resolver.fail("svc", errors.New("i/o timeout"))

	clock.advance(30 * time.Second)
	gw.upstreamDNS.Refresh(context.Background())

	list, err := gw.urlFromDNS(spec)
	if err != nil {
		t.Fatalf("urlFromDNS: %v", err)
	}
	if list.Len() != 2 {
		t.Fatalf("target list holds %d entries thirty seconds into a sixty second stale TTL, want the 2 already found", list.Len())
	}

	// Past the bound the API falls back to its configured target.
	clock.advance(90 * time.Second)
	gw.upstreamDNS.Refresh(context.Background())

	list, err = gw.urlFromDNS(spec)
	if err != nil {
		t.Fatalf("urlFromDNS: %v", err)
	}
	if list.Len() != 1 {
		t.Fatalf("target list holds %d entries past the stale TTL, want the configured target only", list.Len())
	}
	if entry := hostAt(t, list, 0); entry != "h2c://svc:9002" {
		t.Errorf("fell back to %q, want the configured target", entry)
	}
}

// Two APIs, one Service. The second joins an already-resolved name, so
// without the set it joined it would compute the next change against nothing
// and never drain its connection to a terminating pod.
func TestPlanDrains_ForEveryAPIOnASharedHostname(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	gw := newDiscoveryGateway(t, resolver)

	first := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.DrainDeadline = 1
	})
	second := loadDiscoveredAPI(t, gw, "api-2", "h2c://svc:9002", func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.DrainDeadline = 1
	})

	firstConn, firstPeer := net.Pipe()
	secondConn, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()

	trackedFirst := first.dnsDiscovery.conns.track("10.0.0.1:9002", firstConn)
	trackedSecond := second.dnsDiscovery.conns.track("10.0.0.1:9002", secondConn)

	resolver.set("svc", "10.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())

	if !closedWithin(t, trackedFirst, 5*time.Second) {
		t.Error("the first API never closed its connection to the departed pod")
	}
	if !closedWithin(t, trackedSecond, 5*time.Second) {
		t.Error("the second API never closed its connection to the departed pod; " +
			"it joined a hostname that was already resolved, so it had no set to compare against")
	}
}

// A stored definition cannot be rejected, so an API the create endpoint would
// have refused keeps serving on its configured target, and logs why.
// loggedReason reports whether any entry names why the combination was refused.
func loggedReason(entries []*logrus.Entry, want string) bool {
	for _, entry := range entries {
		if strings.Contains(entry.Message, want) {
			return true
		}
	}
	return false
}

// assertRefusedCombination checks one unworkable configuration is refused, is
// left on its configured target, and says why in the log.
func assertRefusedCombination(t *testing.T, configure func(*APISpec), wantLog string) {
	t.Helper()

	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")
	gw := newDiscoveryGateway(t, resolver)

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.APIID = "api-1"
	spec.Proxy.TargetURL = "h2c://svc:9002"
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	configure(spec)

	log, hook := logrustest.NewNullLogger()
	logger := logrus.NewEntry(log)
	gw.setupUpstreamDNSDiscovery(spec, logger)

	if spec.dnsDiscovery != nil {
		t.Fatal("DNS discovery was enabled for a configuration that cannot work")
	}

	// No source, so the Director uses the configured target. One refused for
	// service discovery keeps that.
	if !spec.Proxy.ServiceDiscovery.UseDiscoveryService {
		if list := gw.upstreamTargetList(spec, logger); list != nil {
			t.Errorf("a refused API produced a target list: %v", list.All())
		}
	}

	if !loggedReason(hook.AllEntries(), wantLog) {
		t.Errorf("no log line naming the reason; wanted one containing %q", wantLog)
	}
}

func TestSetupUpstreamDNSDiscovery_RefusedCombinationsKeepServing(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*APISpec)
		wantLog   string
	}{
		{
			name:      "without load balancing",
			configure: func(spec *APISpec) { spec.Proxy.EnableLoadBalancing = false },
			wantLog:   "requires enable_load_balancing",
		},
		{
			name: "alongside service discovery",
			configure: func(spec *APISpec) {
				spec.Proxy.ServiceDiscovery.UseDiscoveryService = true
			},
			wantLog: "cannot be enabled together",
		},
		{
			name:      "a non-h2c upstream",
			configure: func(spec *APISpec) { spec.Proxy.TargetURL = "http://svc:8080" },
			wantLog:   "only supports h2c upstreams",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRefusedCombination(t, tc.configure, tc.wantLog)
		})
	}
}

// The pool keys on the URL host, the authority on req.Host: one varies per
// backend, the other stays steady.
func TestDirector_SendsTheServiceNameAsTheAuthority(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")

	newProxy := func(t *testing.T, configure ...func(*APISpec)) *ReverseProxy {
		t.Helper()

		gw := newDiscoveryGateway(t, resolver)
		gw.SetConfig(config.Config{}, true)

		spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", configure...)

		target, err := url.Parse(spec.Proxy.TargetURL)
		if err != nil {
			t.Fatalf("parse target: %v", err)
		}

		logger := logrus.NewEntry(logrus.New())
		logger.Logger.SetLevel(logrus.PanicLevel)
		return gw.TykNewSingleHostReverseProxy(target, spec, logger)
	}

	t.Run("the address is dialled and the service name is claimed", func(t *testing.T) {
		proxy := newProxy(t)

		req := httptest.NewRequest(http.MethodPost, "http://gateway/greet", nil)
		proxy.Director(req)

		if req.URL.Host != "10.0.0.1:9002" {
			t.Errorf("dialling %q, want the resolved pod address", req.URL.Host)
		}
		if req.Host != "svc:9002" {
			t.Errorf("authority is %q, want the configured service name", req.Host)
		}
		if req.URL.Scheme != "h2c" {
			t.Errorf("scheme is %q, want h2c: rewriting it sends a gRPC upstream HTTP/1.1", req.URL.Scheme)
		}
	})

	t.Run("preserve_host_header still wins", func(t *testing.T) {
		proxy := newProxy(t, func(spec *APISpec) { spec.Proxy.PreserveHostHeader = true })

		req := httptest.NewRequest(http.MethodPost, "http://caller.example.com/greet", nil)
		req.Host = "caller.example.com"
		proxy.Director(req)

		if req.Host != "caller.example.com" {
			t.Errorf("authority is %q; preserve_host_header asked for the client's own Host", req.Host)
		}
		if req.URL.Host != "10.0.0.1:9002" {
			t.Errorf("dialling %q, want the resolved pod address", req.URL.Host)
		}
	})
}

// The Director takes its query from the entry the picker returned, so an
// entry built without one drops it.
func TestBuildUpstreamTarget_KeepsTheConfiguredQuery(t *testing.T) {
	target, err := url.Parse("h2c://svc:9002/base?tenant=acme")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := buildUpstreamTarget(target, "10.0.0.1", "9002")
	if want := "h2c://10.0.0.1:9002/base?tenant=acme"; got != want {
		t.Errorf("buildUpstreamTarget = %q, want %q", got, want)
	}
}
