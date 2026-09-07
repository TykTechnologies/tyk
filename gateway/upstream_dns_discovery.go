package gateway

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/dnspoll"
)

// Upstream DNS discovery: a third source for an API's target list.
//
// The gateway already picks a target per request, in nextTarget, and already
// has two ways to arrive at the list it picks from: a static target_list, and
// service discovery reading a registry over HTTP. What it has never had is a
// source that turns one hostname into the addresses behind it, which is what a
// headless Kubernetes Service requires. This adds that as a third source.
//
// Refreshing is done in the background, by one scheduler for the gateway keyed
// by hostname. That shape comes from the systems that already solve this rather
// than from first principles. Envoy, NGINX, HAProxy and Kong all refresh DNS on
// a timer whenever they hold a connection pool per endpoint and distribute
// across it, and all of them key the work to the cluster, the server template
// or the upstream entity rather than to the route. Envoy states the reason for
// keeping it off the request path directly: it "never synchronously resolves
// DNS in the forwarding path".
//
// Keying by hostname is what makes a background timer affordable. Two thousand
// APIs pointing at fifty Services cost fifty lookups per cycle, not two
// thousand, and one goroutine for the process rather than one per API. It also
// means an API receiving no traffic still discovers pods, which is the property
// resolving on request cannot provide.
//
// The mechanism that makes this work without a new connection pool is that the
// Director sets req.URL.Host and req.Host separately. The HTTP/2 connection
// pool is keyed on req.URL.Host, while the :authority header comes from
// req.Host. Varying the former across pod addresses while leaving the latter as
// the service name yields one connection per pod, each presenting the authority
// the upstream expects.
//
// This only does anything on a headless Service. A ClusterIP resolves to one
// virtual IP, so there is a single address to find, and the cluster dataplane
// binds each connection to a single backend anyway.

const (
	// dnsDiscoveryDefaultInterval is used when RefreshInterval is 0.
	dnsDiscoveryDefaultInterval int64 = 30

	// dnsDiscoveryMinInterval is the floor applied to any positive interval.
	dnsDiscoveryMinInterval int64 = 5

	// dnsDiscoveryLookupTimeout bounds one lookup, so a resolver that hangs
	// does not stall the whole cycle.
	dnsDiscoveryLookupTimeout = 5 * time.Second

	// dnsDiscoveryMaxBackoff caps the interval after repeated failures.
	// Unbounded growth would leave discovery broken long after DNS recovered.
	dnsDiscoveryMaxBackoff = 5 * time.Minute

	// dnsDiscoveryDefaultStaleTTL is used when StaleTTL is 0. Far shorter than
	// Kong's equivalent, which defaults to an hour and drew reports of deleted
	// Kubernetes endpoints still receiving traffic.
	dnsDiscoveryDefaultStaleTTL int64 = 300

	// dnsDiscoveryIdleWait is how long the scheduler sleeps when no hostname is
	// registered. A subscription wakes it, so this only bounds how long a
	// missed wake would go unnoticed.
	dnsDiscoveryIdleWait = time.Minute

	// dnsDiscoveryMinWait floors the sleep between cycles, so a pathological
	// interval cannot turn the loop into a busy wait.
	dnsDiscoveryMinWait = 10 * time.Millisecond

	// dnsDiscoveryJitterFraction is the proportion of the interval added at
	// random to each cycle. Gateways started together otherwise resolve in
	// lockstep, which is the herd effect gRPC's maintainers describe when
	// arguing against TTL-aligned refreshes, and which Envoy's dns_jitter and
	// gRFC A9's ten percent jitter exist to break.
	dnsDiscoveryJitterFraction = 0.1
)

// dnsAddrSet is one published address set for a hostname.
//
// Published by atomic pointer swap and never mutated afterwards, so the request
// path reads it without taking a lock. version increases on every change, which
// is what lets each API cache its rendered target list and rebuild only when
// membership actually moves.
type dnsAddrSet struct {
	version uint64
	addrs   []string
}

// dnsDiscoveryEntry is the scheduler's state for one upstream hostname, shared
// by every API pointing at that name.
type dnsDiscoveryEntry struct {
	host string

	// published is read by the request path and written only by the scheduler.
	published atomic.Pointer[dnsAddrSet]

	// The fields below are guarded by the scheduler's mutex.
	interval    time.Duration
	staleTTL    time.Duration
	refs        int
	nextDue     time.Time
	failures    int
	lastSuccess time.Time
}

// addresses returns the currently published set, or nil before the first
// resolution has completed.
func (e *dnsDiscoveryEntry) addresses() *dnsAddrSet {
	return e.published.Load()
}

// dnsSubscription is what one API asked for, kept so that a release can
// recompute the shared interval and so that a superseded spec cannot release a
// subscription its replacement has taken over.
type dnsSubscription struct {
	host     string
	interval time.Duration
	staleTTL time.Duration
	plan     *dnsDiscoveryPlan
}

// dnsRenderedTargets is one API's target list, built from a published address
// set and reusable until that set changes.
type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

// dnsDiscoveryPlan is what one API resolves. It is computed when the API loads,
// so the request path parses no URLs and reads no configuration.
//
// Its presence on the spec is what turns the feature on for that API: an API
// whose upstream is an IP literal, or is reached over TLS, or which has not
// enabled load balancing, gets no plan and keeps its ordinary behaviour.
type dnsDiscoveryPlan struct {
	target   *url.URL
	host     string
	port     string
	interval time.Duration
	staleTTL time.Duration

	// entry is the shared address set this API reads. Held directly rather than
	// looked up per request.
	entry *dnsDiscoveryEntry

	// fallback is the configured target as a one-entry list, built once at load
	// time. Used until the first resolution has published something, so that
	// window costs no allocation per request and behaves as the API would have
	// without the feature.
	fallback *apidef.HostList

	// rendered caches the target list built from the entry's current version.
	rendered atomic.Pointer[dnsRenderedTargets]
}

// upstreamDNSDiscoveryEnabled reports whether the Director should source this
// API's target list from DNS.
func upstreamDNSDiscoveryEnabled(spec *APISpec) bool {
	return spec != nil && spec.dnsDiscovery != nil
}

// upstreamDNSScheduler refreshes upstream hostnames in the background, one
// entry per distinct hostname, on a single goroutine.
type upstreamDNSScheduler struct {
	mu sync.Mutex

	// entries is keyed by hostname; subscriptions maps an API to the hostname
	// it is currently subscribed to, so a reload can move or drop it.
	entries       map[string]*dnsDiscoveryEntry
	subscriptions map[string]*dnsSubscription

	version uint64
	running bool
	wake    chan struct{}

	// Injectable for tests. Nil means the real implementation.
	lookup func(ctx context.Context, host string) ([]string, error)
	now    func() time.Time
	jitter func(time.Duration) time.Duration

	// lookups counts completed lookups, for tests and benchmarks that assert
	// query volume follows hostnames rather than APIs.
	lookups atomic.Int64
}

func (s *upstreamDNSScheduler) timeNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *upstreamDNSScheduler) resolve(ctx context.Context, host string) ([]string, error) {
	s.lookups.Add(1)

	if s.lookup != nil {
		return s.lookup(ctx, host)
	}

	ctx, cancel := context.WithTimeout(ctx, dnsDiscoveryLookupTimeout)
	defer cancel()

	return net.DefaultResolver.LookupHost(ctx, host)
}

func (s *upstreamDNSScheduler) nextInterval(base time.Duration) time.Duration {
	if s.jitter != nil {
		return s.jitter(base)
	}
	if base <= 0 {
		return base
	}
	span := int64(float64(base) * dnsDiscoveryJitterFraction)
	if span <= 0 {
		return base
	}
	return base + time.Duration(rand.Int63n(span))
}

// subscribe points apiID at the plan's hostname, creating the shared entry if
// this is the first API to ask for it, and returns the entry to read from.
//
// The first resolution runs synchronously, so the API has pod addresses before
// it serves anything rather than falling back to the service name for one
// cycle. Envoy warms a cluster the same way, and NGINX's init-addr exists for
// the same reason.
func (s *upstreamDNSScheduler) subscribe(ctx context.Context, apiID string, plan *dnsDiscoveryPlan) *dnsDiscoveryEntry {
	host, interval, staleTTL := plan.host, plan.interval, plan.staleTTL

	s.mu.Lock()

	if s.entries == nil {
		s.entries = map[string]*dnsDiscoveryEntry{}
		s.subscriptions = map[string]*dnsSubscription{}
	}

	previous, had := s.subscriptions[apiID]
	if had && previous.host != host {
		s.releaseLocked(previous.host)
	}
	s.subscriptions[apiID] = &dnsSubscription{host: host, interval: interval, staleTTL: staleTTL, plan: plan}

	entry, existing := s.entries[host]
	if !existing {
		// Due immediately, and resolved by the loop rather than here. Resolving
		// on this goroutine would put a DNS lookup on the API load path, which
		// is single-threaded and gates the router swap, so a slow resolver
		// would delay every API behind this one. Until the first answer
		// arrives the API uses its configured target, which is what it would
		// have done without the feature.
		entry = &dnsDiscoveryEntry{
			host:     host,
			interval: interval,
			staleTTL: staleTTL,
			nextDue:  s.timeNow(),
			refs:     1,
		}
		s.entries[host] = entry
	} else {
		if !had || previous.host != host {
			entry.refs++
		}
		// Several APIs can share a hostname and ask for different values. They
		// share one refresh and one address set, so the strictest request wins
		// in both cases.
		if interval < entry.interval {
			entry.interval = interval
			if due := s.timeNow().Add(interval); due.Before(entry.nextDue) {
				entry.nextDue = due
			}
		}
		if staleTTL > 0 && (entry.staleTTL <= 0 || staleTTL < entry.staleTTL) {
			entry.staleTTL = staleTTL
		}
	}

	s.ensureRunningLocked(ctx)
	s.mu.Unlock()

	return entry
}

// releaseSubscription drops apiID's subscription, but only if it is still the
// one this plan created.
//
// A reload unloads the definition it replaces, and the replacement has already
// subscribed under the same API ID by then, so an unconditional release from an
// unload hook would drop a live subscription. Comparing the plan identifies
// which of the two is calling.
func (s *upstreamDNSScheduler) releaseSubscription(apiID string, plan *dnsDiscoveryPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subscriptions[apiID]
	if !ok || sub.plan != plan {
		return
	}
	delete(s.subscriptions, apiID)
	s.releaseLocked(sub.host)
}

// releaseAPI drops apiID's subscription, and the shared entry with it when no
// other API wants that hostname.
func (s *upstreamDNSScheduler) releaseAPI(apiID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.subscriptions[apiID]
	if !ok {
		return
	}
	delete(s.subscriptions, apiID)
	s.releaseLocked(sub.host)
}

func (s *upstreamDNSScheduler) releaseLocked(host string) {
	entry, ok := s.entries[host]
	if !ok {
		return
	}
	entry.refs--
	if entry.refs <= 0 {
		delete(s.entries, host)
		return
	}

	// The departing API may have been the one that set the shared interval, so
	// recompute it from what is left. Without this the entry keeps refreshing
	// at the most eager rate ever asked for, forever. Release is rare enough
	// that scanning the subscriptions is cheaper than tracking a multiset.
	shortest, shortestStale := time.Duration(0), time.Duration(0)
	for _, sub := range s.subscriptions {
		if sub.host != host {
			continue
		}
		if shortest == 0 || sub.interval < shortest {
			shortest = sub.interval
		}
		if sub.staleTTL > 0 && (shortestStale == 0 || sub.staleTTL < shortestStale) {
			shortestStale = sub.staleTTL
		}
	}
	if shortest > 0 {
		entry.interval = shortest
	}
	entry.staleTTL = shortestStale
}

func (s *upstreamDNSScheduler) ensureRunningLocked(ctx context.Context) {
	if s.running {
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return
	}

	s.running = true
	s.wake = make(chan struct{}, 1)
	go s.run(ctx)
}

// run is the single refresh goroutine.
func (s *upstreamDNSScheduler) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	for {
		for _, entry := range s.dueEntries() {
			s.refresh(ctx, entry)
		}

		timer := time.NewTimer(s.nextWait())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-s.wake:
			timer.Stop()
		}
	}
}

// nextWait is how long to sleep before the earliest refresh falls due.
//
// Computed after the refresh pass rather than with it, because an entry that
// has just been refreshed holds the nearest deadline. Taking the minimum before
// refreshing excludes exactly those entries, which lets the longest interval in
// the map decide how often the shortest one runs.
func (s *upstreamDNSScheduler) nextWait() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) == 0 {
		return dnsDiscoveryIdleWait
	}

	now := s.timeNow()
	wait := time.Duration(-1)
	for _, entry := range s.entries {
		remaining := entry.nextDue.Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if wait < 0 || remaining < wait {
			wait = remaining
		}
	}

	if wait < dnsDiscoveryMinWait {
		wait = dnsDiscoveryMinWait
	}
	return wait
}

// dueEntries returns the entries whose next refresh has arrived. The scan is
// over distinct hostnames, which is the whole point of keying the scheduler
// this way.
func (s *upstreamDNSScheduler) dueEntries() []*dnsDiscoveryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.timeNow()
	var due []*dnsDiscoveryEntry
	for _, entry := range s.entries {
		if !entry.nextDue.After(now) {
			due = append(due, entry)
		}
	}
	return due
}

// refresh resolves one hostname and publishes the result.
//
// Three outcomes rather than two, because "no addresses" and "no answer" are
// different facts and the systems that already solve this treat them
// differently.
//
// A successful answer with no records is information: the Service has no ready
// endpoints. Envoy's STRICT_DNS drops the hosts outright there. This publishes
// the configured hostname instead, so the API falls back to the behaviour it
// would have had without the feature rather than to an empty target list that
// would route every request to the no-healthy-upstreams sink.
//
// An authoritative answer that the name does not exist is applied at once, for
// the same reason and because there is nothing stale worth preserving. NGINX
// makes the same distinction, removing the peers for a name on NXDOMAIN while
// retaining them on other resolver errors.
//
// Any other failure means the resolver could not be reached, which says nothing
// about whether the pods are still there. The previously published addresses
// are kept and the entry backs off, because discarding a working address set
// would turn a resolver outage into an API outage. That is bounded by the
// entry's stale TTL: once the addresses have gone that long without
// confirmation, the API falls back to its configured target and resolution
// returns to the dial path, which retries per connection.
func (s *upstreamDNSScheduler) refresh(ctx context.Context, entry *dnsDiscoveryEntry) {
	addrs, err := s.resolve(ctx, entry.host)
	addrs = dnspoll.Normalise(addrs)

	s.mu.Lock()
	defer s.mu.Unlock()

	base := entry.interval
	if base <= 0 {
		base = time.Duration(dnsDiscoveryDefaultInterval) * time.Second
	}

	if err != nil {
		entry.failures++
		entry.nextDue = s.timeNow().Add(s.backoffLocked(base, entry.failures))

		if dnsNameNotFound(err) {
			s.publishLocked(entry, []string{entry.host})
			return
		}

		// Nothing has been published yet, so there is no stale set to bound and
		// the request path is already falling back on its own.
		if entry.lastSuccess.IsZero() {
			return
		}
		if entry.staleTTL > 0 && s.timeNow().Sub(entry.lastSuccess) > entry.staleTTL {
			s.publishLocked(entry, []string{entry.host})
		}
		return
	}

	entry.failures = 0
	entry.lastSuccess = s.timeNow()
	entry.nextDue = s.timeNow().Add(s.nextInterval(base))

	if len(addrs) == 0 {
		addrs = []string{entry.host}
	}
	s.publishLocked(entry, addrs)
}

// publishLocked swaps in a new address set unless it matches what is already
// published.
//
// Suppressing an unchanged publish is what keeps each API's rendered target
// list valid across a refresh that found nothing new, and it is why the address
// set is sorted first: CoreDNS shuffles its answers by default, so without the
// sort every refresh would look like a membership change.
func (s *upstreamDNSScheduler) publishLocked(entry *dnsDiscoveryEntry, addrs []string) {
	if current := entry.published.Load(); current != nil && equalAddrs(current.addrs, addrs) {
		return
	}

	s.version++
	entry.published.Store(&dnsAddrSet{version: s.version, addrs: addrs})
}

// dnsNameNotFound reports whether the resolver answered authoritatively that
// the name does not exist, as opposed to failing to answer at all.
func dnsNameNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// backoffLocked grows the interval on consecutive failures, as Envoy's
// dns_failure_refresh_rate and grpc-go's resolver error path both do.
func (s *upstreamDNSScheduler) backoffLocked(base time.Duration, failures int) time.Duration {
	interval := base
	for i := 1; i < failures && interval < dnsDiscoveryMaxBackoff; i++ {
		interval *= 2
	}
	if interval > dnsDiscoveryMaxBackoff {
		interval = dnsDiscoveryMaxBackoff
	}
	return s.nextInterval(interval)
}

func equalAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// planUpstreamDNSDiscovery works out whether spec should resolve its upstream,
// and what it should resolve. It returns nil when the API wants none.
func planUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) *dnsDiscoveryPlan {
	conf := spec.Proxy.DNSDiscovery
	if !conf.Enabled {
		return nil
	}

	if !spec.Proxy.EnableLoadBalancing {
		// DNS discovery is a source; enable_load_balancing is the policy that
		// distributes what a source produces. With the policy off, target
		// selection returns the first entry for every request, so resolving
		// the name would change when resolution happens and nothing else:
		// every request would still land on one pod, which is the defect this
		// exists to fix.
		//
		// Refused rather than silently accepted, because a setting that
		// appears to be on and does nothing is worse than one that says why it
		// is off. The API keeps working on its configured target.
		logger.Error("[PROXY] [DNS DISCOVERY] dns_discovery requires enable_load_balancing; " +
			"it supplies the target list but does not distribute across it. Leaving this API on its configured target")
		return nil
	}

	target, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		logger.WithError(err).Error("[PROXY] [DNS DISCOVERY] Could not parse target URL, DNS discovery disabled for this API")
		return nil
	}

	if tlsUpstreamScheme(target.Scheme) {
		// Refusing TLS upstreams is correctness rather than caution. Sending a
		// request to a pod address means the transport dials an IP literal, and
		// Go derives both SNI and certificate verification from the URL host
		// whenever tls.Config.ServerName is unset, which it always is here. An
		// ordinary service certificate, issued for the service name with no IP
		// SAN, then fails to verify and every request to the API breaks.
		// Measured: dialling the same listener by name verifies, by IP fails
		// with "cannot validate certificate for <ip> because it doesn't contain
		// any IP SANs".
		//
		// Supporting this needs the authority carried into the TLS config, not
		// just into the Host header, and the certificate pinning lookup moved
		// off the dialled address. Out of scope here.
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery does not support TLS upstreams; leaving this API on its configured target")
		return nil
	}

	host, port := splitUpstreamHostPort(target)
	if !resolvableHost(host) {
		// An IP literal, an empty host, or localhost: nothing to discover.
		return nil
	}

	return &dnsDiscoveryPlan{
		target:   target,
		host:     host,
		port:     port,
		interval: resolveDNSDiscoveryInterval(conf.RefreshInterval),
		staleTTL: resolveDNSDiscoveryStaleTTL(conf.StaleTTL),
		fallback: apidef.NewHostListFromList([]string{spec.Proxy.TargetURL}),
	}
}

// setupUpstreamDNSDiscovery subscribes the API to its upstream hostname, or
// unsubscribes it. Called on every load and reload.
//
// Reconciling both ways matters because a reload replaces an API definition
// without unloading it: only definitions that disappear entirely are unloaded,
// so an API that stops wanting discovery has to be released here rather than by
// a hook that will not run.
func (gw *Gateway) setupUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) {
	plan := planUpstreamDNSDiscovery(spec, logger)
	if plan == nil {
		spec.dnsDiscovery = nil
		gw.upstreamDNS.releaseAPI(spec.APIID)
		return
	}

	ctx := gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	plan.entry = gw.upstreamDNS.subscribe(ctx, spec.APIID, plan)
	spec.dnsDiscovery = plan

	// An API that disappears from the register is unloaded rather than
	// reprocessed, so without this its subscription would outlive it and the
	// scheduler would keep resolving a hostname nothing reads. The release is
	// conditional on the plan, so a superseded spec cannot drop the
	// subscription its replacement has already taken over.
	spec.AddUnloadHook(func() { gw.upstreamDNS.releaseSubscription(spec.APIID, plan) })

	logger.WithFields(logrus.Fields{
		"host":             plan.host,
		"refresh_interval": plan.interval.String(),
		"stale_ttl":        plan.staleTTL.String(),
	}).Info("[PROXY] [DNS DISCOVERY] Sourcing the target list from DNS")
}

// resolveDNSDiscoveryInterval applies the default and the floor.
func resolveDNSDiscoveryInterval(seconds int64) time.Duration {
	if seconds <= 0 {
		return time.Duration(dnsDiscoveryDefaultInterval) * time.Second
	}
	if seconds < dnsDiscoveryMinInterval {
		return time.Duration(dnsDiscoveryMinInterval) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// resolveDNSDiscoveryStaleTTL applies the default, and treats a negative value
// as never giving up on the last known good set.
func resolveDNSDiscoveryStaleTTL(seconds int64) time.Duration {
	switch {
	case seconds < 0:
		return 0
	case seconds == 0:
		return time.Duration(dnsDiscoveryDefaultStaleTTL) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// urlFromDNS returns the API's target list from the address set the scheduler
// has published for its upstream hostname.
//
// This is on the request path, so it does no resolution and takes no lock. It
// reads the published set through an atomic pointer and reuses the target list
// it built last time unless the set has changed, which it usually has not.
func (gw *Gateway) urlFromDNS(spec *APISpec) (*apidef.HostList, error) {
	plan := spec.dnsDiscovery
	if plan == nil {
		return spec.Proxy.StructuredTargetList, nil
	}

	// Before the first resolution has published anything, and if the plan was
	// somehow never subscribed, fall back to the configured target. Built once
	// at load time, so a resolver outage does not allocate per request while
	// the entry backs off.
	if plan.entry == nil {
		return plan.fallback, nil
	}
	set := plan.entry.addresses()
	if set == nil {
		return plan.fallback, nil
	}

	if rendered := plan.rendered.Load(); rendered != nil && rendered.version == set.version {
		return rendered.list, nil
	}

	targets := make([]string, 0, len(set.addrs))
	for _, addr := range set.addrs {
		targets = append(targets, buildUpstreamTarget(plan.target, addr, plan.port))
	}

	list := apidef.NewHostListFromList(targets)
	plan.rendered.Store(&dnsRenderedTargets{version: set.version, list: list})
	return list, nil
}

// splitUpstreamHostPort separates the target's host from its port, supplying
// the scheme's default port when the URL carries none. The port has to be
// carried explicitly because resolution answers with bare addresses.
func splitUpstreamHostPort(target *url.URL) (host, port string) {
	host, port = target.Hostname(), target.Port()
	if port != "" {
		return host, port
	}

	switch strings.ToLower(target.Scheme) {
	case "https", "wss":
		return host, "443"
	default:
		// http, h2c, ws, and anything unrecognised.
		return host, "80"
	}
}

// tlsUpstreamScheme reports whether proxying to this scheme negotiates TLS with
// the upstream, and therefore verifies a certificate against the dialled host.
func tlsUpstreamScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "https", "wss", "tls":
		return true
	default:
		return false
	}
}

// resolvableHost reports whether a host is a DNS name whose membership can
// change. IP literals resolve to themselves and localhost is not a Service.
func resolvableHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return !strings.EqualFold(host, "localhost")
}

// buildUpstreamTarget renders one resolved address as a target list entry.
//
// The scheme is preserved verbatim, h2c included. That is the point of the
// EnsureTransport change that accompanies this: the h2c transport is selected
// from the request's scheme after the Director has run, so an entry written as
// http:// here would be sent to a gRPC upstream over HTTP/1.1.
func buildUpstreamTarget(target *url.URL, addr, port string) string {
	entry := target.Scheme + "://" + net.JoinHostPort(addr, port)
	if target.Path != "" && target.Path != "/" {
		entry += target.Path
	}
	return entry
}
