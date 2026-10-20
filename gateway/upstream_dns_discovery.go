package gateway

import (
	"context"
	"net"
	"net/url"
	"strings"
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

var dnsDiscoveryClock = time.Now

type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

type dnsDiscoveryPlan struct {
	target *url.URL
	host   string
	port   string

	interval time.Duration
	staleTTL time.Duration
	drain    time.Duration

	sub       *dnsdiscovery.Subscription
	noTargets *apidef.HostList
	rendered  atomic.Pointer[dnsRenderedTargets]

	conns      *upstreamConnRegistry
	generation uint64

	logger           *logrus.Entry
	unresolvedLogged atomic.Bool
	expiredLogged    atomic.Bool
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

	return &dnsDiscoveryPlan{
		target:    target,
		host:      host,
		port:      port,
		interval:  resolveDNSDiscoveryInterval(conf),
		staleTTL:  resolveDNSDiscoveryStaleTTL(conf),
		drain:     resolveDNSDiscoveryDrainTimeout(conf),
		noTargets: apidef.NewHostList(),
		logger:    logger,
	}
}

func (gw *Gateway) setupUpstreamDNSDiscovery(spec *APISpec, logger *logrus.Entry) {
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

	if plan.drain >= 0 {
		plan.conns = gw.upstreamConns.get(spec.APIID, logger)
		plan.generation = plan.conns.newGeneration()
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

	if !spec.dnsDiscoveryHooked {
		spec.dnsDiscoveryHooked = true
		spec.AddUnloadHook(func() {
			if current := spec.dnsDiscovery.Load(); current != nil {
				current.sub.Release()
			}
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

func (gw *Gateway) releaseUpstreamDNSDiscovery(spec *APISpec) {
	if spec == nil {
		return
	}

	plan := spec.dnsDiscovery.Load()
	if plan == nil || plan.conns == nil {
		gw.upstreamConns.abandon(spec.APIID)
		return
	}
	gw.upstreamConns.release(spec.APIID, plan.drain)
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
			Warning("[PROXY] [DNS DISCOVERY] Upstream hostname did not resolve at load; refusing requests until it does")
	}
}

func (p *dnsDiscoveryPlan) registry() *upstreamConnRegistry {
	if p == nil {
		return nil
	}
	return p.conns
}

func (p *dnsDiscoveryPlan) onAddressSet(state *dnsdiscovery.State) {
	if p.conns == nil || state == nil {
		return
	}

	addrs := make([]string, 0, len(state.Addrs))
	for _, addr := range state.Addrs {
		addrs = append(addrs, net.JoinHostPort(addr, p.port))
	}
	p.conns.update(p.generation, state.Version, addrs, p.drain)
}

func resolveDNSDiscoveryInterval(conf apidef.DNSDiscoveryConfig) time.Duration {
	return dnsdiscovery.NormaliseInterval(time.Duration(conf.RefreshInterval))
}

func resolveDNSDiscoveryStaleTTL(conf apidef.DNSDiscoveryConfig) time.Duration {
	if conf.StaleTTL <= 0 {
		return 0
	}
	return time.Duration(conf.StaleTTL)
}

func resolveDNSDiscoveryDrainTimeout(conf apidef.DNSDiscoveryConfig) time.Duration {
	draining := conf.ConnectionDraining
	if draining == nil || !draining.Enabled {
		return dnsDiscoveryDrainDisabled
	}
	if draining.Timeout <= 0 {
		return dnsDiscoveryDefaultDrainTimeout
	}
	return time.Duration(draining.Timeout)
}

func (gw *Gateway) urlFromDNS(spec *APISpec) (*apidef.HostList, upstreamSelection) {
	plan := spec.dnsDiscovery.Load()
	if plan == nil {
		return spec.Proxy.StructuredTargetList, upstreamSelection{}
	}

	state := plan.sub.State()
	if !state.Selectable(plan.staleTTL, dnsDiscoveryClock) {
		plan.logRefusal(state)
		return plan.noTargets, upstreamSelection{}
	}
	if plan.expiredLogged.Load() {
		plan.expiredLogged.Store(false)
	}

	sel := upstreamSelection{generation: plan.generation, version: state.Version}

	if rendered := plan.rendered.Load(); rendered != nil && rendered.version == state.Version {
		return rendered.list, sel
	}

	targets := make([]string, 0, len(state.Addrs))
	for _, addr := range state.Addrs {
		targets = append(targets, buildUpstreamTarget(plan.target, addr, plan.port))
	}

	list := apidef.NewHostListFromList(targets)
	plan.rendered.Store(&dnsRenderedTargets{version: state.Version, list: list})
	return list, sel
}

func (p *dnsDiscoveryPlan) logRefusal(state *dnsdiscovery.State) {
	if p.logger == nil {
		return
	}

	switch {
	case state == nil || state.Outcome == dnsdiscovery.Unresolved:
		if p.unresolvedLogged.CompareAndSwap(false, true) {
			p.logger.WithField("host", p.host).
				Warning("[PROXY] [DNS DISCOVERY] No addresses resolved yet; refusing requests until the hostname resolves")
		}
	case state.Usable():
		if p.expiredLogged.CompareAndSwap(false, true) {
			p.logger.WithFields(logrus.Fields{
				"host":      p.host,
				"stale_ttl": p.staleTTL.String(),
			}).Warning("[PROXY] [DNS DISCOVERY] Lookups failing past stale_ttl; refusing requests until one succeeds")
		}
	}
}

func splitUpstreamHostPort(target *url.URL) (host, port string) {
	host, port = target.Hostname(), target.Port()
	if port != "" {
		return host, port
	}

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
