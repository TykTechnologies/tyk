package gateway

import (
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/dnspoll"
)

// Upstream DNS load balancing: the reverse-proxy adapter over internal/dnspoll.
//
// The gateway already picks a target per request, in nextTarget. What it has
// never had is a source of addresses that changes: the host list is static
// configuration, and Kubernetes pod IPs are not. This closes that gap by
// re-resolving the upstream hostname on a timer and rewriting the host list
// with the pod addresses it returns.
//
// The mechanism it relies on is that the Director sets req.URL.Host and
// req.Host separately. The HTTP/2 connection pool is keyed on req.URL.Host,
// while the :authority header comes from req.Host. Varying the former across
// pod addresses while leaving the latter as the service name therefore yields
// one connection per pod, each presenting a correct authority — with the stock
// pool, no new connection pool required.
//
// This only does anything on a headless Service. A ClusterIP resolves to one
// virtual IP, so the poller finds a single address, and the cluster dataplane
// binds each connection to a single backend anyway.

// upstreamDNSBinding is one API's live poller, together with the host list it
// writes into and a key describing what it is polling.
type upstreamDNSBinding struct {
	key      string
	poller   *dnspoll.Poller
	hostList *apidef.HostList
}

// upstreamDNSRegistry holds one binding per API ID.
//
// Pollers are owned by the gateway rather than by the APISpec because a reload
// does not unload the spec it replaces: api_loader only calls Unload on specs
// that have disappeared from the register, so a spec that is merely rebuilt is
// dropped without its hooks ever running. A poller owned by the spec would
// therefore leak a goroutine and a ticker on every reload, for every API. This
// registry lets a rebuilt spec adopt the poller that is already running for it,
// which also avoids a rediscovery gap across reloads.
type upstreamDNSRegistry struct {
	mu       sync.Mutex
	bindings map[string]*upstreamDNSBinding
}

func (r *upstreamDNSRegistry) get(apiID string) *upstreamDNSBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bindings[apiID]
}

// put installs b for apiID, stopping and returning whatever it replaced.
func (r *upstreamDNSRegistry) put(apiID string, b *upstreamDNSBinding) {
	r.mu.Lock()
	if r.bindings == nil {
		r.bindings = map[string]*upstreamDNSBinding{}
	}
	previous := r.bindings[apiID]
	r.bindings[apiID] = b
	r.mu.Unlock()

	if previous != nil {
		previous.poller.Stop()
	}
}

// release stops b and forgets it, but only if apiID still maps to it. A reload
// may already have replaced the binding, and stopping the live poller because
// a superseded spec was unloaded would silently end discovery for that API.
func (r *upstreamDNSRegistry) release(apiID string, b *upstreamDNSBinding) {
	r.mu.Lock()
	current, ok := r.bindings[apiID]
	if ok && current == b {
		delete(r.bindings, apiID)
	}
	r.mu.Unlock()

	if ok && current == b {
		b.poller.Stop()
	}
}

// upstreamDNSLoadBalancingEnabled reports whether this API is having its target
// list driven by DNS. It is true only when a poller was actually started for
// the spec, so an API whose target is an IP literal, or which has no pollable
// host, keeps its ordinary single-target behaviour even with the feature on.
func upstreamDNSLoadBalancingEnabled(spec *APISpec) bool {
	return spec != nil && spec.upstreamDNSPoller != nil
}

// setupUpstreamDNSLoadBalancing points spec's target list at a DNS poller, if
// the feature is enabled and the API's upstream is a name worth polling. It
// populates spec.Proxy.StructuredTargetList before returning, so the first
// request already has targets.
func (gw *Gateway) setupUpstreamDNSLoadBalancing(spec *APISpec, logger *logrus.Entry) {
	conf := spec.Proxy.DNSLoadBalancing
	if !conf.Enabled {
		return
	}

	interval, enabled := config.ResolveDNSRefreshInterval(conf.RefreshInterval)
	if !enabled {
		return
	}

	target, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		logger.WithError(err).Error("[PROXY] [UPSTREAM DNS] Could not parse target URL, upstream DNS load balancing disabled for this API")
		return
	}

	if tlsUpstreamScheme(target.Scheme) {
		// Refusing TLS upstreams is not caution, it is correctness. Rewriting
		// the target to a pod address means the transport dials an IP literal,
		// and Go derives both SNI and certificate verification from the URL
		// host whenever tls.Config.ServerName is unset — which it always is
		// here. An ordinary service certificate, issued for the service name
		// with no IP SAN, then fails to verify and every request to the API
		// breaks. Measured: dialling the same listener by name verifies, by IP
		// fails with "cannot validate certificate for <ip> because it doesn't
		// contain any IP SANs".
		//
		// Supporting this needs the authority carried into the TLS config, not
		// just into the Host header. Out of scope here.
		logger.WithField("scheme", target.Scheme).
			Warning("[PROXY] [UPSTREAM DNS] Upstream DNS load balancing does not support TLS upstreams; leaving this API on its configured target")
		return
	}

	host, port := splitUpstreamHostPort(target)
	if !pollableHost(host) {
		// An IP literal, an empty host, or localhost: nothing to discover, and
		// starting a goroutine to rediscover it would be pure cost.
		return
	}

	// Everything that decides what the poller does and what it produces. A
	// reload that changes none of it can keep the poller it already has.
	key := strings.Join([]string{target.Scheme, host, port, target.Path, interval.String()}, "|")

	if existing := gw.upstreamDNS.get(spec.APIID); existing != nil && existing.key == key {
		spec.Proxy.StructuredTargetList = existing.hostList
		spec.upstreamDNSPoller = existing.poller
		spec.AddUnloadHook(func() { gw.upstreamDNS.release(spec.APIID, existing) })
		return
	}

	logger = logger.WithFields(logrus.Fields{
		"prefix":   "upstream-dns",
		"host":     host,
		"interval": interval.String(),
	})

	// Seed the list with the configured target, so that a failure to resolve
	// leaves the API working exactly as it does today rather than with no
	// targets at all.
	hostList := apidef.NewHostListFromList([]string{spec.Proxy.TargetURL})

	poller, err := dnspoll.New(dnspoll.Config{
		Host:     host,
		Interval: interval,
		OnChange: func(addresses []string) {
			targets := make([]string, 0, len(addresses))
			for _, addr := range addresses {
				targets = append(targets, buildUpstreamTarget(target, addr, port))
			}
			hostList.Set(targets)
			logger.WithField("targets", targets).Info("[PROXY] [UPSTREAM DNS] Upstream address set changed")
		},
	})
	if err != nil {
		logger.WithError(err).Error("[PROXY] [UPSTREAM DNS] Could not create poller, upstream DNS load balancing disabled for this API")
		return
	}

	// Start resolves once synchronously, so the host list holds pod addresses
	// rather than the service name before the API serves anything.
	poller.Start(gw.ctx)

	binding := &upstreamDNSBinding{key: key, poller: poller, hostList: hostList}
	gw.upstreamDNS.put(spec.APIID, binding)

	spec.Proxy.StructuredTargetList = hostList
	spec.upstreamDNSPoller = poller
	spec.AddUnloadHook(func() { gw.upstreamDNS.release(spec.APIID, binding) })
}

// splitUpstreamHostPort separates the target's host from its port, supplying
// the scheme's default port when the URL carries none. The port has to be
// carried explicitly because the poller resolves a bare name and returns bare
// addresses.
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

// pollableHost reports whether a host is a DNS name whose membership can
// change. IP literals resolve to themselves and localhost is not a Service.
func pollableHost(host string) bool {
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
