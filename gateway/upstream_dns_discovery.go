package gateway

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
)

// Upstream DNS discovery is a third source for an API's target list, alongside
// the static target_list and service discovery. Resolution itself lives in
// internal/dnsdiscovery. Nothing here is gRPC-specific, and it is only useful
// where a name resolves to one address per backend, such as a headless Service.

// Defaults for the periods, applied when the configured value is 0. The drain
// default matches the Kubernetes default terminationGracePeriodSeconds.
const (
	dnsDiscoveryDefaultInterval      int64 = 30
	dnsDiscoveryDefaultStaleTTL      int64 = 300
	dnsDiscoveryDefaultDrainDeadline int64 = 30

	// dnsDiscoveryDrainDisabled is the sentinel for a negative DrainDeadline.
	dnsDiscoveryDrainDisabled = time.Duration(-1)
)

// dnsRenderedTargets caches the target list built from one published address
// set.
type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

// dnsDiscoveryPlan holds what one API resolves, computed at load so the request
// path parses no URLs. Its presence on the spec turns the feature on.
type dnsDiscoveryPlan struct {
	target *url.URL
	host   string
	port   string

	interval time.Duration
	staleTTL time.Duration
	drain    time.Duration

	// sub is this API's handle on the shared address set for its upstream name.
	sub *dnsdiscovery.Subscription

	// fallback is the configured target as a one-entry list, used whenever the
	// resolved set is unusable.
	fallback *apidef.HostList

	rendered atomic.Pointer[dnsRenderedTargets]

	// conns is nil when draining is disabled.
	conns *upstreamConnRegistry

	// mu guards lastAddrs, which is only touched on a membership change.
	mu        sync.Mutex
	lastAddrs []string
}

// upstreamDNSDiscoveryEnabled reports whether the Director should source this
// API's target list from DNS.
func upstreamDNSDiscoveryEnabled(spec *APISpec) bool {
	return spec != nil && spec.dnsDiscovery != nil
}

// upstreamDrainRegistry returns the registry the API's transports dial
// through, or nil when there is nothing to track.
func upstreamDrainRegistry(spec *APISpec) *upstreamConnRegistry {
	if spec == nil || spec.dnsDiscovery == nil {
		return nil
	}
	return spec.dnsDiscovery.conns
}

// planUpstreamDNSDiscovery works out what spec should resolve, returning nil
// when the API wants nothing resolved or asks for something unsupported.
func planUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) *dnsDiscoveryPlan {
	conf := spec.Proxy.DNSDiscovery
	if !conf.Enabled {
		return nil
	}

	if !spec.Proxy.EnableLoadBalancing {
		logger.Error("[PROXY] [DNS DISCOVERY] dns_discovery requires enable_load_balancing; " +
			"it supplies the target list but does not distribute across it. Leaving this API on its configured target")
		return nil
	}

	// Two sources for one list, with no tie-break. Service discovery is left
	// running, since an existing API may be relying on it.
	if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
		logger.Error("[PROXY] [DNS DISCOVERY] dns_discovery and service_discovery both supply the target list " +
			"and cannot be enabled together. Leaving this API on service discovery")
		return nil
	}

	target, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		logger.WithError(err).Error("[PROXY] [DNS DISCOVERY] Could not parse target URL, DNS discovery disabled for this API")
		return nil
	}

	// TLS is called out separately because it is the case people ask about.
	// Dialling a backend means dialling an IP literal, and Go derives SNI and
	// verification from the URL host, so a service certificate with no IP SAN
	// fails on every request.
	if tlsUpstreamScheme(target.Scheme) {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery does not support TLS upstreams; leaving this API on its configured target")
		return nil
	}

	// Scoped to cleartext HTTP/2, the transport that pins to one backend by
	// holding one connection per authority.
	if !strings.EqualFold(target.Scheme, "h2c") {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery only supports h2c upstreams; leaving this API on its configured target")
		return nil
	}

	host, port := splitUpstreamHostPort(target)
	if !dnsdiscovery.Resolvable(host) {
		// An IP literal, an empty host, or localhost: nothing to discover.
		return nil
	}

	plan := &dnsDiscoveryPlan{
		target:   target,
		host:     host,
		port:     port,
		interval: resolveDNSDiscoveryInterval(conf.RefreshInterval),
		staleTTL: resolveDNSDiscoveryStaleTTL(conf.StaleTTL),
		drain:    resolveDNSDiscoveryDrainDeadline(conf.DrainDeadline),
		fallback: apidef.NewHostListFromList([]string{spec.Proxy.TargetURL}),
	}

	if plan.drain >= 0 {
		plan.conns = newUpstreamConnRegistry()
	}

	return plan
}

// setupUpstreamDNSDiscovery subscribes the API to its upstream hostname, or
// unsubscribes it. A reload replaces a definition without unloading it, so an
// API that stops wanting discovery is released here.
func (gw *Gateway) setupUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) {
	previous := spec.dnsDiscovery

	disable := func() {
		spec.dnsDiscovery = nil
		gw.upstreamDNS.ReleaseKey(spec.APIID)
		previous.retire()
	}

	plan := planUpstreamDNSDiscovery(spec, logger)
	if plan == nil {
		disable()
		return
	}

	ctx := gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	sub, err := gw.upstreamDNS.Subscribe(ctx, spec.APIID, dnsdiscovery.Config{
		Host:     plan.host,
		Interval: plan.interval,
		StaleTTL: plan.staleTTL,
		OnChange: plan.onAddressSet,
	})
	if err != nil {
		logger.WithError(err).Error("[PROXY] [DNS DISCOVERY] Could not subscribe to the upstream hostname; " +
			"leaving this API on its configured target")
		disable()
		return
	}

	plan.sub = sub
	spec.dnsDiscovery = plan
	previous.retire()

	// Registered once per spec, and releasing what the spec holds at the time
	// rather than the plan captured here.
	if !spec.dnsDiscoveryHooked {
		spec.dnsDiscoveryHooked = true
		spec.AddUnloadHook(func() {
			current := spec.dnsDiscovery
			if current == nil {
				return
			}
			current.sub.Release()
			current.retire()
		})
	}

	drain := "disabled"
	if plan.drain >= 0 {
		drain = plan.drain.String()
	}

	logger.WithFields(logrus.Fields{
		"host":             plan.host,
		"refresh_interval": plan.interval.String(),
		"stale_ttl":        plan.staleTTL.String(),
		"drain_deadline":   drain,
	}).Info("[PROXY] [DNS DISCOVERY] Sourcing the target list from DNS")
}

// retire closes whatever the plan owns. Safe on a nil plan.
func (p *dnsDiscoveryPlan) retire() {
	if p == nil {
		return
	}
	p.conns.close()
}

// onAddressSet runs when the address set for this API's upstream changes. The
// target list is rendered on the request path, so what happens here is
// retirement: a departed address stops being selected at once, and nothing
// else would close its connections.
func (p *dnsDiscoveryPlan) onAddressSet(state *dnsdiscovery.State) {
	var addrs []string
	if state != nil {
		addrs = state.Addrs
	}

	p.mu.Lock()
	was := p.lastAddrs
	p.lastAddrs = addrs
	p.mu.Unlock()

	if p.conns == nil {
		return
	}

	for _, addr := range dnsdiscovery.Removed(was, addrs) {
		p.conns.drain(net.JoinHostPort(addr, p.port), p.drain)
	}

	// An address back before its deadline keeps the connections it already had,
	// which the pool is still holding and would not re-dial.
	for _, addr := range dnsdiscovery.Removed(addrs, was) {
		p.conns.cancelDrain(net.JoinHostPort(addr, p.port))
	}
}

// resolveDNSDiscoveryInterval applies the default and the floor.
func resolveDNSDiscoveryInterval(seconds int64) time.Duration {
	if seconds <= 0 {
		seconds = dnsDiscoveryDefaultInterval
	}
	return dnsdiscovery.NormaliseInterval(time.Duration(seconds) * time.Second)
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

// resolveDNSDiscoveryDrainDeadline applies the default, and treats a negative
// value as never force-closing a departed address's connections.
func resolveDNSDiscoveryDrainDeadline(seconds int64) time.Duration {
	switch {
	case seconds < 0:
		return dnsDiscoveryDrainDisabled
	case seconds == 0:
		return time.Duration(dnsDiscoveryDefaultDrainDeadline) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// urlFromDNS returns the API's target list from the published address set. It
// runs on the request path, so it resolves nothing and takes no lock. The
// fallback covers nothing resolved yet, an empty answer, and a resolver
// unreachable past the stale TTL.
func (gw *Gateway) urlFromDNS(spec *APISpec) (*apidef.HostList, error) {
	plan := spec.dnsDiscovery
	if plan == nil {
		return spec.Proxy.StructuredTargetList, nil
	}

	state := plan.sub.State()
	if !state.Usable() {
		return plan.fallback, nil
	}

	if rendered := plan.rendered.Load(); rendered != nil && rendered.version == state.Version {
		return rendered.list, nil
	}

	targets := make([]string, 0, len(state.Addrs))
	for _, addr := range state.Addrs {
		targets = append(targets, buildUpstreamTarget(plan.target, addr, plan.port))
	}

	list := apidef.NewHostListFromList(targets)
	plan.rendered.Store(&dnsRenderedTargets{version: state.Version, list: list})
	return list, nil
}

// splitUpstreamHostPort separates host from port, supplying a default when the
// URL carries none. The port is kept because resolution answers with bare
// addresses.
func splitUpstreamHostPort(target *url.URL) (host, port string) {
	host, port = target.Hostname(), target.Port()
	if port != "" {
		return host, port
	}

	// Only h2c reaches here, and cleartext HTTP/2 has no port of its own.
	return host, "80"
}

// tlsUpstreamScheme reports whether proxying to this scheme negotiates TLS,
// and so verifies a certificate against the dialled host.
func tlsUpstreamScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "https", "wss", "tls":
		return true
	default:
		return false
	}
}

// buildUpstreamTarget renders one resolved address as a target list entry,
// preserving everything the configured target carries. The scheme selects the
// h2c transport after the Director has run, and the Director takes the query
// from whichever entry the picker returned.
func buildUpstreamTarget(target *url.URL, addr, port string) string {
	var entry strings.Builder

	entry.WriteString(target.Scheme)
	entry.WriteString("://")

	if target.User != nil {
		entry.WriteString(target.User.String())
		entry.WriteByte('@')
	}

	entry.WriteString(net.JoinHostPort(addr, port))

	if target.Path != "" && target.Path != "/" {
		entry.WriteString(target.Path)
	}

	if target.RawQuery != "" {
		entry.WriteByte('?')
		entry.WriteString(target.RawQuery)
	}

	return entry.String()
}
