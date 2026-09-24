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

const (
	dnsDiscoveryDefaultDrainTimeout = 30 * time.Second

	dnsDiscoveryWarmTimeout = time.Second

	dnsDiscoveryDrainDisabled = time.Duration(-1)
)

type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

// dnsDiscoveryPlan is non-nil on a spec exactly when discovery is on.
type dnsDiscoveryPlan struct {
	target *url.URL
	host   string
	port   string

	interval time.Duration
	staleTTL time.Duration
	drain    time.Duration

	sub       *dnsdiscovery.Subscription
	fallback  *apidef.HostList
	noTargets *apidef.HostList
	rendered  atomic.Pointer[dnsRenderedTargets]

	// conns is nil when draining is disabled.
	conns      *upstreamConnRegistry
	apiID      string
	registries *upstreamConnRegistries

	logger         *logrus.Entry
	fallbackLogged atomic.Bool

	mu        sync.Mutex
	lastAddrs []string
}

func upstreamDNSDiscoveryEnabled(spec *APISpec) bool {
	return spec != nil && spec.dnsDiscovery.Load() != nil
}

func upstreamDrainRegistry(spec *APISpec) *upstreamConnRegistry {
	if spec == nil {
		return nil
	}
	return spec.dnsDiscovery.Load().registry()
}

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

	// A resolved backend is an IP literal, which no service certificate covers.
	if tlsUpstreamScheme(target.Scheme) {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery does not support TLS upstreams; leaving this API on its configured target")
		return nil
	}

	if !strings.EqualFold(target.Scheme, "h2c") {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery only supports h2c upstreams; leaving this API on its configured target")
		return nil
	}

	host, port := splitUpstreamHostPort(target)
	if !dnsdiscovery.Resolvable(host) {
		logger.WithField("host", host).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery needs a resolvable hostname, not an IP literal or localhost; leaving this API on its configured target")
		return nil
	}

	plan := &dnsDiscoveryPlan{
		target:    target,
		host:      host,
		port:      port,
		interval:  resolveDNSDiscoveryInterval(conf),
		staleTTL:  resolveDNSDiscoveryStaleTTL(conf),
		drain:     resolveDNSDiscoveryDrainTimeout(conf),
		fallback:  apidef.NewHostListFromList([]string{spec.Proxy.TargetURL}),
		noTargets: apidef.NewHostList(),
		logger:    logger,
	}

	if plan.drain >= 0 {
		plan.conns = newUpstreamConnRegistry(logger)
	}

	return plan
}

// setupUpstreamDNSDiscovery reconciles both ways: an API that stops asking is released here.
func (gw *Gateway) setupUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) {
	previous := spec.dnsDiscovery.Load()

	disable := func() {
		spec.dnsDiscovery.Store(nil)
		gw.upstreamDNS.ReleaseKey(spec.APIID)
		gw.upstreamConns.abandon(spec.APIID)
	}

	plan := planUpstreamDNSDiscovery(spec, logger)
	if plan == nil {
		disable()
		return
	}

	if plan.conns != nil {
		plan.apiID = spec.APIID
		plan.registries = &gw.upstreamConns
		plan.conns = gw.upstreamConns.claim(spec.APIID, plan, plan.conns)
	} else {
		gw.upstreamConns.abandon(spec.APIID)
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
	spec.dnsDiscovery.Store(plan)
	previous.retire()

	// Once per spec; the hook releases whatever plan the spec holds when it fires.
	if !spec.dnsDiscoveryHooked {
		spec.dnsDiscoveryHooked = true
		spec.AddUnloadHook(func() {
			current := spec.dnsDiscovery.Load()
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

	staleTTL := "unlimited"
	if plan.staleTTL > 0 {
		staleTTL = plan.staleTTL.String()
	}

	logger.WithFields(logrus.Fields{
		"host":             plan.host,
		"refresh_interval": plan.interval.String(),
		"stale_ttl":        staleTTL,
		"drain_timeout":    drain,
	}).Info("[PROXY] [DNS DISCOVERY] Sourcing the target list from DNS")
}

func (gw *Gateway) warmUpstreamDNS() {
	ctx := gw.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, dnsDiscoveryWarmTimeout)
	defer cancel()

	for _, host := range gw.upstreamDNS.Warm(ctx) {
		mainLog.WithField("host", host).
			Warning("[PROXY] [DNS DISCOVERY] Upstream hostname did not resolve at load; serving its configured target until it does")
	}
}

// registry is nil-safe: an API with no plan, or with draining disabled, has none.
func (p *dnsDiscoveryPlan) registry() *upstreamConnRegistry {
	if p == nil {
		return nil
	}
	return p.conns
}

func (p *dnsDiscoveryPlan) retire() {
	if p == nil {
		return
	}
	if p.registries != nil {
		p.registries.release(p.apiID, p, p.drain)
		return
	}
	p.conns.retire(p.drain)
}

// onAddressSet holds the diff and the drains it implies in one critical section.
func (p *dnsDiscoveryPlan) onAddressSet(state *dnsdiscovery.State) {
	var addrs []string
	if state != nil {
		addrs = state.Addrs
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	was := p.lastAddrs
	p.lastAddrs = addrs

	if state != nil && state.Outcome == dnsdiscovery.Unreachable && len(was) > 0 && p.logger != nil {
		p.logger.WithFields(logrus.Fields{
			"host":      p.host,
			"stale_ttl": p.staleTTL.String(),
		}).Warning("[PROXY] [DNS DISCOVERY] Resolver unreachable past stale_ttl; dropping the last known addresses")
	}

	if p.conns == nil {
		return
	}

	for _, addr := range dnsdiscovery.Removed(was, addrs) {
		p.conns.drain(net.JoinHostPort(addr, p.port), p.drain)
	}

	var members map[string]struct{}
	if state != nil && state.Outcome != dnsdiscovery.Unresolved {
		members = make(map[string]struct{}, len(addrs))
		for _, addr := range addrs {
			members[net.JoinHostPort(addr, p.port)] = struct{}{}
		}
	}
	p.conns.reconcile(members, p.drain)

	// A returning address keeps the connections the transport still holds.
	for _, addr := range dnsdiscovery.Added(was, addrs) {
		p.conns.cancelDrain(net.JoinHostPort(addr, p.port))
	}
}

func resolveDNSDiscoveryInterval(conf apidef.DNSDiscoveryConfig) time.Duration {
	return dnsdiscovery.NormaliseInterval(time.Duration(conf.RefreshInterval))
}

func resolveDNSDiscoveryStaleTTL(conf apidef.DNSDiscoveryConfig) time.Duration {
	if conf.StaleTTL <= 0 {
		return dnsdiscovery.StaleTTLUnlimited
	}
	return time.Duration(conf.StaleTTL)
}

func resolveDNSDiscoveryDrainTimeout(conf apidef.DNSDiscoveryConfig) time.Duration {
	draining := conf.ConnectionDraining
	if draining != nil && !draining.Enabled {
		return dnsDiscoveryDrainDisabled
	}
	if draining == nil || draining.Timeout <= 0 {
		return dnsDiscoveryDefaultDrainTimeout
	}
	return time.Duration(draining.Timeout)
}

// urlFromDNS runs on the request path: it resolves nothing and takes no lock.
func (gw *Gateway) urlFromDNS(spec *APISpec) (*apidef.HostList, error) {
	plan := spec.dnsDiscovery.Load()
	if plan == nil {
		return spec.Proxy.StructuredTargetList, nil
	}

	state := plan.sub.State()
	if !state.Usable() {
		if state == nil || state.Outcome == dnsdiscovery.Unresolved {
			if plan.logger != nil && plan.fallbackLogged.CompareAndSwap(false, true) {
				plan.logger.WithField("host", plan.host).
					Warning("[PROXY] [DNS DISCOVERY] No addresses resolved yet; serving the configured target")
			}
			return plan.fallback, nil
		}
		return plan.noTargets, nil
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

// splitUpstreamHostPort keeps the port, since resolution answers with bare addresses.
func splitUpstreamHostPort(target *url.URL) (host, port string) {
	host, port = target.Hostname(), target.Port()
	if port != "" {
		return host, port
	}

	// Only h2c reaches here, and cleartext HTTP/2 has no port of its own.
	return host, "80"
}

func tlsUpstreamScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "https", "wss", "tls":
		return true
	default:
		return false
	}
}

func buildUpstreamTarget(target *url.URL, addr, port string) string {
	entry := *target
	entry.Host = net.JoinHostPort(addr, port)
	entry.Fragment = ""
	entry.RawFragment = ""
	if entry.Path == "/" && entry.RawPath == "" {
		entry.Path = ""
	}
	return entry.String()
}
