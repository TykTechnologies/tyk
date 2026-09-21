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
// the static target_list and service discovery. Resolution lives in
// internal/dnsdiscovery.

// Applied when the configured value is 0. The drain default matches the
// Kubernetes default terminationGracePeriodSeconds.
const (
	dnsDiscoveryDefaultInterval      int64 = 30
	dnsDiscoveryDefaultStaleTTL      int64 = 300
	dnsDiscoveryDefaultDrainDeadline int64 = 30

	dnsDiscoveryDrainDisabled = time.Duration(-1)
)

type dnsRenderedTargets struct {
	version uint64
	list    *apidef.HostList
}

// dnsDiscoveryPlan holds what one API resolves. Its presence on the spec turns
// the feature on.
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

	// Dialling a backend means dialling an IP literal, and Go derives SNI and
	// verification from the URL host, so a service certificate fails on every
	// request.
	if tlsUpstreamScheme(target.Scheme) {
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [DNS DISCOVERY] DNS discovery does not support TLS upstreams; leaving this API on its configured target")
		return nil
	}

	// h2c is the transport that pins to one backend, by holding one connection
	// per authority.
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

	// Once per spec, releasing what the spec holds at the time rather than the
	// plan captured here.
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

// onAddressSet retires what a departed address leaves behind. The target list
// itself is rendered on the request path.
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

	// An address back before its deadline keeps the connections the transport
	// is still holding and would not re-dial.
	for _, addr := range dnsdiscovery.Removed(addrs, was) {
		p.conns.cancelDrain(net.JoinHostPort(addr, p.port))
	}
}

func resolveDNSDiscoveryInterval(seconds int64) time.Duration {
	if seconds <= 0 {
		seconds = dnsDiscoveryDefaultInterval
	}
	return dnsdiscovery.NormaliseInterval(time.Duration(seconds) * time.Second)
}

// A negative value means never give up on the last known good set, which the
// scheduler spells as zero.
func resolveDNSDiscoveryStaleTTL(seconds int64) time.Duration {
	switch {
	case seconds < 0:
		return 0
	case seconds == 0:
		return time.Duration(dnsDiscoveryDefaultStaleTTL) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

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
// runs on the request path, so it resolves nothing and takes no lock.
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

// splitUpstreamHostPort keeps the port because resolution answers with bare
// addresses.
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

// buildUpstreamTarget keeps everything the configured target carries. The
// scheme selects the h2c transport after the Director has run, and the
// Director takes the query from whichever entry the picker returned.
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
