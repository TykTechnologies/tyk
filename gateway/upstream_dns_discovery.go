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

// A third source for an API's target list, after target_list and service
// discovery. Resolution lives in internal/dnsdiscovery.

// Defaults applied when the configured value is 0.
const (
	dnsDiscoveryDefaultInterval      int64 = 30
	dnsDiscoveryDefaultStaleTTL      int64 = 300
	dnsDiscoveryDefaultDrainDeadline int64 = 30

	// The configured stale_ttl that never gives up on the last good set.
	dnsDiscoveryStaleTTLUnlimited int64 = -1

	dnsDiscoveryDrainDisabled = time.Duration(-1)
)

type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

// A non-nil plan on the spec turns the feature on.
type dnsDiscoveryPlan struct {
	target *url.URL
	host   string
	port   string

	interval time.Duration
	staleTTL time.Duration
	drain    time.Duration

	sub      *dnsdiscovery.Subscription
	fallback *apidef.HostList
	rendered atomic.Pointer[dnsRenderedTargets]

	// conns is nil when draining is disabled.
	conns *upstreamConnRegistry

	mu        sync.Mutex
	lastAddrs []string
}

func upstreamDNSDiscoveryEnabled(spec *APISpec) bool {
	return spec != nil && spec.dnsDiscovery != nil
}

func upstreamDrainRegistry(spec *APISpec) *upstreamConnRegistry {
	if spec == nil || spec.dnsDiscovery == nil {
		return nil
	}
	return spec.dnsDiscovery.conns
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

	// Left on service discovery, which an existing API may be relying on.
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

	// Dialling a backend means dialling an IP literal, which no service
	// certificate covers.
	if tlsUpstreamScheme(target.Scheme) {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery does not support TLS upstreams; leaving this API on its configured target")
		return nil
	}

	// h2c pins to one backend, holding one connection per authority.
	if !strings.EqualFold(target.Scheme, "h2c") {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery only supports h2c upstreams; leaving this API on its configured target")
		return nil
	}

	host, port := splitUpstreamHostPort(target)
	if !dnsdiscovery.Resolvable(host) {
		return nil
	}

	plan := &dnsDiscoveryPlan{
		target:   target,
		host:     host,
		port:     port,
		interval: resolveDNSDiscoveryInterval(conf),
		staleTTL: resolveDNSDiscoveryStaleTTL(conf),
		drain:    resolveDNSDiscoveryDrainDeadline(conf),
		fallback: apidef.NewHostListFromList([]string{spec.Proxy.TargetURL}),
	}

	if plan.drain >= 0 {
		plan.conns = newUpstreamConnRegistry()
	}

	return plan
}

// Reconciles both ways: a reload can replace a definition without unloading
// it, so an API that stops asking for discovery is released here.
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

	// Once per spec. The hook releases whatever plan the spec holds when it
	// fires, which may not be this one.
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

func (p *dnsDiscoveryPlan) retire() {
	if p == nil {
		return
	}
	p.conns.close()
}

// onAddressSet retires what a departed address leaves. The diff and the drains
// it implies are one critical section, or two deliveries interleave and arm a
// drain the other's cancel has already passed.
func (p *dnsDiscoveryPlan) onAddressSet(state *dnsdiscovery.State) {
	var addrs []string
	if state != nil {
		addrs = state.Addrs
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	was := p.lastAddrs
	p.lastAddrs = addrs

	if p.conns == nil {
		return
	}

	for _, addr := range dnsdiscovery.Removed(was, addrs) {
		p.conns.drain(net.JoinHostPort(addr, p.port), p.drain)
	}

	// A returning address keeps the connections the transport still holds.
	for _, addr := range dnsdiscovery.Added(was, addrs) {
		p.conns.cancelDrain(net.JoinHostPort(addr, p.port))
	}
}

// Zero means "use the default" throughout, as it does for every other duration
// in an API definition. StaleTTL also takes -1 for "never give up", the
// spelling session lifetimes use. apidef.RuleDNSDiscovery rejects the rest.

func resolveDNSDiscoveryInterval(conf apidef.DNSDiscoveryConfig) time.Duration {
	seconds := conf.RefreshInterval
	if seconds <= 0 {
		seconds = dnsDiscoveryDefaultInterval
	}
	return dnsdiscovery.NormaliseInterval(time.Duration(seconds) * time.Second)
}

func resolveDNSDiscoveryStaleTTL(conf apidef.DNSDiscoveryConfig) time.Duration {
	switch {
	case conf.StaleTTL == dnsDiscoveryStaleTTLUnlimited:
		return dnsdiscovery.StaleTTLUnlimited
	case conf.StaleTTL <= 0:
		return time.Duration(dnsDiscoveryDefaultStaleTTL) * time.Second
	}
	return time.Duration(conf.StaleTTL) * time.Second
}

func resolveDNSDiscoveryDrainDeadline(conf apidef.DNSDiscoveryConfig) time.Duration {
	if conf.DrainDisabled {
		return dnsDiscoveryDrainDisabled
	}
	if conf.DrainDeadline <= 0 {
		return time.Duration(dnsDiscoveryDefaultDrainDeadline) * time.Second
	}
	return time.Duration(conf.DrainDeadline) * time.Second
}

// On the request path: resolves nothing, takes no lock.
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

// The port is kept because resolution answers with bare addresses.
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

// The scheme selects the h2c transport after the Director runs, and the
// Director takes the query from the entry the picker returned.
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
