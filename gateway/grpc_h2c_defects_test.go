package gateway

// Reproduction tests for three defects in the h2c (plaintext HTTP/2, i.e. gRPC)
// upstream path. All three were found while investigating why gRPC upstreams do
// not load-balance or discover autoscaled pods.
//
// THESE TESTS FAIL ON MASTER BY DESIGN. Each asserts the behaviour the gateway
// should have; each currently demonstrates the defect instead. They are written
// to be the regression gate for the fixes, not to be green today.
//
//	TestH2C_LoadBalancing_UsesHTTP2          — h2c + enable_load_balancing sends HTTP/1.1
//	TestH2C_DNSCache_IsApplied               — dns_cache silently does not apply to h2c
//	TestH2C_TransportRebuild_ClosesOldConns  — max_conn_time leaks an h2c connection per rebuild
//	TestH2C_Upstream_RoundRobin_Distributes  — gRPC upstreams never load-balance at all
//
// Run with:
//	go test ./gateway/ -run 'TestH2C_' -v

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// mockDomain points the process-wide DNS mock at ips for the duration of the
// test, then restores whatever was registered before.
//
// There is exactly one mock server per process: net.DefaultResolver can only
// point at one, so every InitDNSMock caller shares it. Registering through
// PushDomains keeps each test's mappings from outliving it and colliding with
// the next one — TestReverseProxyDnsCache in particular installs its own set
// and runs after this file.
func mockDomain(t *testing.T, host string, ips []string) *test.DnsMockHandle {
	t.Helper()

	// The gateway package only creates its global mock when EnableTestDNSMock
	// is set, which it is not, so take a handle on the process-wide one here.
	// InitDNSMock returns the same server to every caller.
	handle, err := test.InitDNSMock(map[string][]string{}, nil)
	if err != nil {
		t.Fatalf("init dns mock: %v", err)
	}

	pull := handle.PushDomains(map[string][]string{host + ".": ips}, nil)
	t.Cleanup(pull)

	assertResolves(t, host, ips)
	return handle
}

// assertResolves fails the test unless host resolves to exactly len(ips)
// addresses, so a later assertion cannot fail for want of a working mock.
func assertResolves(t *testing.T, host string, ips []string) {
	t.Helper()

	resolved, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		t.Fatalf("mocked resolver did not answer for %s: %v", host, err)
	}
	if len(resolved) != len(ips) {
		t.Fatalf("mocked resolver returned %v for %s, want %v", resolved, host, ips)
	}
}

// newH2CUpstream starts a plaintext HTTP/2 (h2c) server, the shape a gRPC
// upstream presents to the gateway. The handler records the protocol each
// request arrived over, which is how these tests tell HTTP/2 from HTTP/1.1.
func newH2CUpstream(t *testing.T, onRequest func(r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(
		h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if onRequest != nil {
				onRequest(r)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}), &http2.Server{}),
	)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestH2C_LoadBalancing_UsesHTTP2 reproduces defect D-3.
//
// EnsureTransport rewrites "h2c://" to "http://" (gateway/reverse_proxy.go:149)
// and is called from the load-balancing target path (:170, :199). The h2c
// transport is only selected when outReq.URL.Scheme == "h2c" (:836), which by
// then is "http". So enabling enable_load_balancing on an h2c API silently
// downgrades it to HTTP/1.1 — the gateway speaks the wrong protocol to a gRPC
// server, which is a hard failure for real gRPC rather than a slow path.
func TestH2C_LoadBalancing_UsesHTTP2(t *testing.T) {
	var mu sync.Mutex
	var protos []string

	upstream := newH2CUpstream(t, func(r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
	})
	h2cURL := strings.Replace(upstream.URL, "http://", "h2c://", 1)

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/lb-h2c/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = h2cURL
		// The only difference from a working h2c API.
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.Targets = []string{h2cURL}
	})

	_, _ = ts.Run(t, test.TestCase{Path: "/lb-h2c/", Code: http.StatusOK})

	mu.Lock()
	defer mu.Unlock()
	if len(protos) == 0 {
		t.Fatal("upstream received no requests")
	}
	for i, got := range protos {
		if got != "HTTP/2.0" {
			t.Errorf("request %d reached the h2c upstream over %q, want %q.\n"+
				"enable_load_balancing downgraded an h2c upstream to HTTP/1.1; "+
				"a real gRPC server would reject this outright.", i, got, "HTTP/2.0")
		}
	}
}

// TestH2C_LoadBalancing_Disabled_UsesHTTP2 is the control for D-3. The same API
// without enable_load_balancing must reach the upstream over HTTP/2. If this
// one fails, the test above proves nothing.
func TestH2C_LoadBalancing_Disabled_UsesHTTP2(t *testing.T) {
	var mu sync.Mutex
	var protos []string

	upstream := newH2CUpstream(t, func(r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
	})
	h2cURL := strings.Replace(upstream.URL, "http://", "h2c://", 1)

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/plain-h2c/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = h2cURL
	})

	_, _ = ts.Run(t, test.TestCase{Path: "/plain-h2c/", Code: http.StatusOK})

	mu.Lock()
	defer mu.Unlock()
	if len(protos) == 0 {
		t.Fatal("upstream received no requests")
	}
	if protos[0] != "HTTP/2.0" {
		t.Fatalf("control failed: plain h2c API reached upstream over %q, want HTTP/2.0. "+
			"The D-3 test above is meaningless until this passes.", protos[0])
	}
}

// TestH2C_DNSCache_IsApplied reproduces defect D-2.
//
// The dns cache is wired only into http.Transport.DialContext
// (gateway/reverse_proxy.go:426). The h2c transport builds its own dialer with a
// raw net.Dial (:838-844), bypassing dnsCacheManager.WrapDialer entirely. A
// customer who enables dns_cache does not get it on h2c APIs, and gets no
// indication of that.
func TestH2C_DNSCache_IsApplied(t *testing.T) {
	const upstreamHost = "h2c-dns-target.com"

	ts := StartTest(nil)
	defer ts.Close()

	upstream := newH2CUpstream(t, nil)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	// Point the mocked resolver at the loopback listener the upstream is on.
	mockDomain(t, upstreamHost, []string{"127.0.0.1"})

	ts.Gw.dnsCacheManager.InitDNSCaching(60*time.Second, 60*time.Second)
	defer ts.Gw.dnsCacheManager.DisposeCache()

	globalConf := ts.Gw.GetConfig()
	globalConf.DnsCache.Enabled = true
	globalConf.DnsCache.TTL = 60
	globalConf.DnsCache.MultipleIPsHandleStrategy = config.NoCacheStrategy
	ts.Gw.SetConfig(globalConf)
	ts.Gw.DoReload()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/h2c-dns/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
	})

	_, _ = ts.Run(t, test.TestCase{Path: "/h2c-dns/", Code: http.StatusOK})

	storage := ts.Gw.dnsCacheManager.CacheStorage()
	if storage == nil {
		t.Fatal("dns cache storage is nil despite dns_cache being enabled")
	}
	if _, found := storage.Get(upstreamHost); !found {
		t.Errorf("after proxying to an h2c upstream at %q, the dns cache holds no entry for it.\n"+
			"The h2c transport dials with a raw net.Dial and bypasses the cached dialer, "+
			"so dns_cache silently does not apply to h2c APIs.", upstreamHost)
	}
}

// connCounter tracks how many TCP connections a test upstream has accepted and
// how many are still open.
//
// Counting via http.Server.ConnState does NOT work for h2c: h2c.NewHandler
// hijacks the connection to hand it to the HTTP/2 server, so every connection
// reports StateHijacked immediately and the server stops reporting on it
// entirely. Wrapping the listener is the only way to observe the real lifetime.
type connCounter struct {
	net.Listener
	accepted int64
	live     int64
}

func (l *connCounter) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&l.accepted, 1)
	atomic.AddInt64(&l.live, 1)
	return &countedConn{Conn: c, parent: l}, nil
}

type countedConn struct {
	net.Conn
	parent *connCounter
	once   sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { atomic.AddInt64(&c.parent.live, -1) })
	return c.Conn.Close()
}

// TestH2C_TransportRebuild_ClosesOldConns reproduces defect D-1.
//
// On rebuild the gateway retires only the HTTP/1 transport — oldTransport is
// HTTPTransport.transport and only that gets CloseIdleConnections()
// (gateway/reverse_proxy.go:1289-1315). The h2ctransport field (:902) is
// dropped without being closed. A standalone http2.Transport has
// IdleConnTimeout == 0, so its ClientConns never self-close, and the readLoop
// goroutine keeps them reachable so GC does not collect them either.
//
// Consequence: max_conn_time — the currently recommended mitigation for gRPC
// upstream pod discovery — leaks one TCP connection and its goroutines per
// rebuild, for the life of the process.
func TestH2C_TransportRebuild_ClosesOldConns(t *testing.T) {
	upstream := httptest.NewUnstartedServer(
		h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}), &http2.Server{}),
	)
	counter := &connCounter{Listener: upstream.Listener}
	upstream.Listener = counter
	upstream.Start()
	defer upstream.Close()

	h2cURL := strings.Replace(upstream.URL, "http://", "h2c://", 1)

	ts := StartTest(nil)
	defer ts.Close()

	// Force a transport rebuild between every request.
	globalConf := ts.Gw.GetConfig()
	globalConf.MaxConnTime = 1
	ts.Gw.SetConfig(globalConf)
	ts.Gw.DoReload()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/h2c-rebuild/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = h2cURL
	})

	const rebuilds = 5
	for i := 0; i < rebuilds; i++ {
		_, _ = ts.Run(t, test.TestCase{Path: "/h2c-rebuild/", Code: http.StatusOK})
		// MaxConnTime is in seconds and the check is `time.Since(created) > d`.
		time.Sleep(1100 * time.Millisecond)
	}
	// Give the upstream a moment to observe any closes.
	time.Sleep(500 * time.Millisecond)

	accepted := atomic.LoadInt64(&counter.accepted)
	live := atomic.LoadInt64(&counter.live)
	t.Logf("upstream accepted %d connections over %d rebuilds; %d still open", accepted, rebuilds, live)

	// Guard against a vacuous pass: if the transport was never actually rebuilt
	// there is only ever one connection and the leak assertion proves nothing.
	if accepted < 2 {
		t.Fatalf("upstream accepted only %d connection(s) across %d rebuilds — the transport "+
			"was not rebuilt, so this test is not exercising the defect", accepted, rebuilds)
	}

	// One live connection is expected: the transport currently in use. Anything
	// approaching `accepted` means every superseded h2c transport is still
	// holding its connection open.
	if live > 2 {
		t.Errorf("after %d rebuilds (%d connections accepted) the h2c upstream still has %d live "+
			"connections, want <= 2.\nSuperseded h2c transports are never closed, so max_conn_time "+
			"leaks a connection and its goroutines on every rebuild.", rebuilds, accepted, live)
	}
}

// TestH2C_Upstream_MaxConnTime_Rebalances tests the mitigation, not the defect.
//
// max_conn_time is the only knob that currently causes an h2c upstream to be
// re-dialled, and it is therefore the workaround a customer would be told to
// set while waiting for real load balancing. This asks whether that workaround
// actually redistributes traffic across a headless Service's pods.
//
// It does not balance. The h2c transport dials with a bare net.Dial
// (gateway/reverse_proxy.go:840-842), and net.Dial walks the resolved address
// list in order, only falling through to the next address when one fails to
// connect — so it always takes whatever the resolver put first.
//
// This test uses a fixed-order DNS mock, so "first" is the same pod every time
// and the re-pin is total. Note what that does and does not prove: against a
// resolver that randomises record order (CoreDNS's loadbalance plugin, in the
// default kubeadm Corefile, and Docker's embedded DNS) each rebuild becomes an
// independent draw and traffic spreads statistically. The invariant that holds
// in BOTH cases is the one that matters: max_conn_time re-rolls a connection, it
// never distributes requests, so the granularity is the connection and the
// outcome depends on the operator's resolver rather than on Tyk. Combined with
// D-1 — each superseded transport leaks its connection — it is a weak,
// environment-dependent mitigation with a guaranteed leak attached.
func TestH2C_Upstream_MaxConnTime_Rebalances(t *testing.T) {
	const upstreamHost = "grpc-upstream-churn.test"

	pods, port := startH2CPodSet(t, 2)

	ips := make([]string, 0, len(pods))
	for _, p := range pods {
		ips = append(ips, p.ip)
	}

	mockDomain(t, upstreamHost, ips)

	ts := StartTest(nil)
	defer ts.Close()

	// Rebuild the transport between every request.
	globalConf := ts.Gw.GetConfig()
	globalConf.MaxConnTime = 1
	ts.Gw.SetConfig(globalConf)
	ts.Gw.DoReload()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/h2c-churn/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
	})

	const rebuilds = 6
	for i := 0; i < rebuilds; i++ {
		_, _ = ts.Run(t, test.TestCase{Path: "/h2c-churn/", Code: http.StatusOK})
		time.Sleep(1100 * time.Millisecond)
	}

	var totalConns int64
	for _, p := range pods {
		hits := atomic.LoadInt64(&p.hits)
		conns := atomic.LoadInt64(&p.conns.accepted)
		totalConns += conns
		t.Logf("  %s (%s:%s): %d requests, %d TCP connection(s) accepted", p.id, p.ip, port, hits, conns)
	}

	// Guard against a vacuous pass: without real churn there is nothing to spread.
	if totalConns < 2 {
		t.Fatalf("only %d connection(s) dialled across %d rebuild windows — max_conn_time "+
			"did not churn the transport, so this test is not exercising the mitigation", totalConns, rebuilds)
	}

	for _, p := range pods {
		if atomic.LoadInt64(&p.conns.accepted) == 0 {
			t.Errorf("after %d transport rebuilds (%d connections dialled in total), pod %s (%s) was "+
				"never dialled even once.\nmax_conn_time re-dials, but net.Dial walks the resolved "+
				"address list in order and only advances past an address that fails to connect, so with "+
				"this fixed-order resolver every rebuild re-pins to the same pod. Against a shuffling "+
				"resolver it would spread only by chance. Either way it re-rolls a connection rather than "+
				"distributing requests, and combined with D-1 (each superseded h2c transport leaks its "+
				"connection) it is not a usable load-balancing workaround for h2c APIs.",
				rebuilds, totalConns, p.id, p.ip)
		}
	}
}

// h2cPod is one backend replica in a simulated headless Service: an h2c server
// bound to its own loopback IP, tagging every response with its identity so the
// caller can attribute traffic.
type h2cPod struct {
	id    string
	ip    string
	srv   *httptest.Server
	conns *connCounter
	hits  int64

	mu         sync.Mutex
	protos     map[string]int // request protocol -> count
	authoritys map[string]int // request :authority -> count
}

// authorities returns the set of :authority values this pod was addressed with.
func (p *h2cPod) authorities() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]int, len(p.authoritys))
	for a, n := range p.authoritys {
		out[a] = n
	}
	return out
}

// protocols returns the set of protocols this pod was reached over.
func (p *h2cPod) protocols() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]int, len(p.protos))
	for proto, n := range p.protos {
		out[proto] = n
	}
	return out
}

// podAddrCandidates returns local IPv4 addresses this host can bind, most
// preferred first. Loopback aliases are ideal and work unconditionally on Linux
// (where 127.0.0.0/8 is entirely local), which is where CI runs. macOS only
// assigns 127.0.0.1 unless an operator adds an alias, so real interface
// addresses are offered as a fallback to keep the test meaningful on a laptop.
func podAddrCandidates() []string {
	candidates := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}

	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return candidates
	}
	for _, a := range ifaceAddrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
			continue
		}
		candidates = append(candidates, ipNet.IP.String())
	}
	return candidates
}

// startH2CPodSet starts n h2c backends, each on its own IP but all on the SAME
// port — which is exactly what a headless Service looks like to a client: one
// name, one port, N pod addresses. Returns the pods and the shared port.
func startH2CPodSet(t *testing.T, n int) ([]*h2cPod, string) {
	t.Helper()

	candidates := podAddrCandidates()

	// Claim a port on the first candidate, then hold every listener open so
	// nothing can steal the port from underneath the set.
	probe, err := net.Listen("tcp", candidates[0]+":0")
	if err != nil {
		t.Skipf("cannot bind %s: %v", candidates[0], err)
	}
	_, port, err := net.SplitHostPort(probe.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	listeners := []net.Listener{probe}
	ips := []string{candidates[0]}
	for _, ip := range candidates[1:] {
		if len(listeners) == n {
			break
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
		if err != nil {
			continue // address not assigned on this host, or port taken there
		}
		listeners = append(listeners, ln)
		ips = append(ips, ip)
	}

	if len(listeners) < n {
		for _, ln := range listeners {
			ln.Close()
		}
		t.Skipf("need %d distinct local IPv4 addresses sharing port %s, found %d (%v).\n"+
			"On macOS add a loopback alias first:  sudo ifconfig lo0 alias 127.0.0.2 up\n"+
			"On Linux this always works, so CI gates on this test regardless.",
			n, port, len(listeners), ips)
	}

	pods := make([]*h2cPod, 0, n)
	for i, ln := range listeners {
		pod := &h2cPod{
			id: fmt.Sprintf("pod-%d", i+1), ip: ips[i],
			protos: map[string]int{}, authoritys: map[string]int{},
		}

		counter := &connCounter{Listener: ln}
		pod.conns = counter

		srv := httptest.NewUnstartedServer(
			h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&pod.hits, 1)
				pod.mu.Lock()
				pod.protos[r.Proto]++
				// For HTTP/2 the server surfaces :authority as r.Host.
				pod.authoritys[r.Host]++
				pod.mu.Unlock()
				w.Header().Set("X-Upstream-Pod", pod.id)
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, pod.id)
			}), &http2.Server{}),
		)
		srv.Listener = counter
		srv.Start()
		t.Cleanup(srv.Close)

		pod.srv = srv
		pods = append(pods, pod)
	}

	return pods, port
}

// TestH2C_Upstream_RoundRobin_Distributes is the gate for upstream DNS load
// balancing: it asserts what the upstream ticket asks for — "Gateway resolves
// all pod IPs for a Kubernetes service" and "round-robins gRPC requests across
// the resolved pod IPs" — against a two-pod headless Service.
//
// Both halves have to hold together, which is why they are asserted in one
// test. Distribution alone is not enough: the target list is what the h2c
// scheme is read from, so an implementation that spread requests but wrote
// http:// entries would send HTTP/1.1 to a gRPC server, which a real one
// rejects outright. And HTTP/2 alone is what master already does, to a single
// pod.
//
// The disabled arm is the control. It pins to one pod, which is the behaviour
// on master with or without grpc_round_robin_load_balancing: that flag is read
// only by the coprocess plugin dispatcher (coprocess_grpc.go) and never reaches
// the upstream transport. Keeping it here records that the new option, not some
// ambient change, is what distributes the traffic.
func TestH2C_Upstream_RoundRobin_Distributes(t *testing.T) {
	const (
		upstreamHost = "grpc-upstream-lb.test"
		requests     = 50
	)

	pods, port := startH2CPodSet(t, 2)

	ips := make([]string, 0, len(pods))
	for _, p := range pods {
		ips = append(ips, p.ip)
	}

	// One name, N pod addresses — a headless Service.
	mockDomain(t, upstreamHost, ips)
	t.Logf("%s resolves to %v (a %d-pod headless Service)", upstreamHost, ips, len(ips))

	for _, enabled := range []bool{true, false} {
		name := "upstream_dns_lb_disabled"
		if enabled {
			name = "upstream_dns_lb_enabled"
		}

		t.Run(name, func(t *testing.T) {
			for _, p := range pods {
				atomic.StoreInt64(&p.hits, 0)
				p.mu.Lock()
				p.protos = map[string]int{}
				p.authoritys = map[string]int{}
				p.mu.Unlock()
			}

			ts := StartTest(nil)
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/h2c-upstream-lb/"
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
				// Per-API, alongside enable_load_balancing and
				// service_discovery: which upstream to rediscover is a property
				// of this API, not of the gateway.
				spec.Proxy.DNSLoadBalancing.Enabled = enabled
				spec.Proxy.DNSLoadBalancing.RefreshInterval = 10
			})

			for i := 0; i < requests; i++ {
				_, _ = ts.Run(t, test.TestCase{Path: "/h2c-upstream-lb/", Code: http.StatusOK})
			}

			var served int64
			var idle []string
			for _, p := range pods {
				hits := atomic.LoadInt64(&p.hits)
				served += hits
				if hits == 0 {
					idle = append(idle, fmt.Sprintf("%s (%s)", p.id, p.ip))
				}
				t.Logf("  %s (%s:%s): %3d/%d requests, %d TCP connection(s) accepted, protocols %v",
					p.id, p.ip, port, hits, requests, atomic.LoadInt64(&p.conns.accepted), p.protocols())
			}

			if served != requests {
				t.Fatalf("pods served %d requests in total, want %d — the traffic did not "+
					"reach the h2c upstreams and nothing below is meaningful", served, requests)
			}

			if !enabled {
				// Control: without the option nothing discovers the second pod,
				// so the whole run multiplexes onto one connection to one pod.
				// If this ever spreads, the enabled arm above proves nothing.
				if len(idle) != len(pods)-1 {
					t.Errorf("control: with upstream_dns_load_balancing disabled, %d of %d pods were idle, "+
						"want %d. Traffic is expected to pin to a single pod, because the h2c transport "+
						"has no resolver and its connection pool is keyed on the authority. If it spreads "+
						"here, the enabled arm is not measuring the new option.",
						len(idle), len(pods), len(pods)-1)
				}
				return
			}

			if len(idle) > 0 {
				t.Fatalf("with upstream_dns_load_balancing enabled, %d of %d pods received NO traffic: %s.\n"+
					"Every address the Service resolves to should appear in the target list and take a "+
					"share of the requests.", len(idle), len(pods), strings.Join(idle, ", "))
			}

			// Round-robin over a stable address set is exact, so anything other
			// than an even split means targets are being picked from a list
			// that is not the resolved one.
			want := int64(requests) / int64(len(pods))
			tolerance := want / 5 // 20%, absorbing where the run starts in the rotation
			for _, p := range pods {
				hits := atomic.LoadInt64(&p.hits)
				if diff := hits - want; diff > tolerance || diff < -tolerance {
					t.Errorf("%s (%s) served %d of %d requests, want %d ± %d — the requests reached every "+
						"pod but are not evenly distributed across them",
						p.id, p.ip, hits, requests, want, tolerance)
				}
			}

			// The other half of the claim: those requests must still be gRPC.
			// EnsureTransport used to rewrite h2c:// to http:// on the
			// load-balancing path, which downgraded exactly this case.
			for _, p := range pods {
				for proto, n := range p.protocols() {
					if proto != "HTTP/2.0" {
						t.Errorf("%s (%s) was reached %d time(s) over %q, want HTTP/2.0.\n"+
							"Load-balanced h2c targets must keep their scheme, or the gateway speaks "+
							"HTTP/1.1 to a gRPC server.", p.id, p.ip, n, proto)
					}
				}
			}

			// Each pod is DIALLED at its own address but must be ADDRESSED by
			// the service name. Those are two different fields — the pool is
			// keyed on the URL host, the :authority comes from the Host header —
			// and keeping them apart is what lets one connection per pod carry
			// an authority the upstream recognises. A pod IP here would break
			// anything that routes on :authority or checks a certificate
			// against it.
			wantAuthority := fmt.Sprintf("%s:%s", upstreamHost, port)
			for _, p := range pods {
				for authority, n := range p.authorities() {
					if authority != wantAuthority {
						t.Errorf("%s (%s) was addressed %d time(s) with :authority %q, want %q.\n"+
							"The pod address belongs in the dialled URL, not in the Host header.",
							p.id, p.ip, n, authority, wantAuthority)
					}
				}
			}
		})
	}
}
