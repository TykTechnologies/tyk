package gateway

// Regression tests for four defects in the h2c (plaintext HTTP/2, so gRPC)
// upstream path. Each one failed on master.

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

// One mock server per process: net.DefaultResolver can only point at one.
func mockDomain(t *testing.T, host string, ips []string) *test.DnsMockHandle {
	t.Helper()

	// InitDNSMock returns the same process-wide server to every caller.
	handle, err := test.InitDNSMock(map[string][]string{}, nil)
	if err != nil {
		t.Fatalf("init dns mock: %v", err)
	}

	pull := handle.PushDomains(map[string][]string{host + ".": ips}, nil)
	t.Cleanup(pull)

	assertResolves(t, host, ips)
	return handle
}

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

// The shape a gRPC upstream presents. Records the protocol per request.
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

// Target selection rewrote h2c:// to http:// before the transport was chosen
// from the scheme, downgrading any h2c API with load balancing on.
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

// The control for the test above.
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

// The h2c transport dialled with a raw net.Dial, bypassing the DNS cache.
func TestH2C_DNSCache_IsApplied(t *testing.T) {
	const upstreamHost = "h2c-dns-target.com"

	ts := StartTest(nil)
	defer ts.Close()

	upstream := newH2CUpstream(t, nil)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

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

// ConnState cannot count h2c: NewHandler hijacks each connection, so it
// reports StateHijacked and nothing after.
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

// A rebuild retired only the HTTP/1 transport, dropping the h2c one unclosed.
// A standalone http2.Transport has IdleConnTimeout 0, so its ClientConns never
// self-close and their readLoops keep them from being collected.
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
	time.Sleep(500 * time.Millisecond)

	accepted := atomic.LoadInt64(&counter.accepted)
	live := atomic.LoadInt64(&counter.live)
	t.Logf("upstream accepted %d connections over %d rebuilds; %d still open", accepted, rebuilds, live)

	// Without a rebuild there is one connection and nothing is proved.
	if accepted < 2 {
		t.Fatalf("upstream accepted only %d connection(s) across %d rebuilds — the transport "+
			"was not rebuilt, so this test is not exercising the defect", accepted, rebuilds)
	}

	// One live connection is expected, the transport currently in use.
	if live > 2 {
		t.Errorf("after %d rebuilds (%d connections accepted) the h2c upstream still has %d live "+
			"connections, want <= 2.\nSuperseded h2c transports are never closed, so max_conn_time "+
			"leaks a connection and its goroutines on every rebuild.", rebuilds, accepted, live)
	}
}

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

func (p *h2cPod) authorities() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]int, len(p.authoritys))
	for a, n := range p.authoritys {
		out[a] = n
	}
	return out
}

func (p *h2cPod) protocols() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]int, len(p.protos))
	for proto, n := range p.protos {
		out[proto] = n
	}
	return out
}

// Bindable local IPv4 addresses, preferred first. Loopback aliases always
// work on Linux, where CI runs; macOS only assigns 127.0.0.1.
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

// n backends on their own IPs sharing one port, as a headless Service.
func startH2CPodSet(t *testing.T, n int) ([]*h2cPod, string) {
	t.Helper()

	candidates := podAddrCandidates()

	// Held open, so nothing steals the port from the set.
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

// Distribution alone is not enough: the target list is where the h2c scheme
// is read from, so entries written http:// would send HTTP/1.1 to a gRPC
// server. The disabled arm is the control, and pins to one pod.
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
				// Discovery supplies the list, load balancing spreads it.
				spec.Proxy.EnableLoadBalancing = enabled
				spec.Proxy.DNSDiscovery.Enabled = enabled
				spec.Proxy.DNSDiscovery.RefreshInterval = 10
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
				// Nothing discovers pod 2, so all of it goes down one
				// connection.
				if len(idle) != len(pods)-1 {
					t.Errorf("control: with dns_discovery disabled, %d of %d pods were idle, "+
						"want %d. Traffic is expected to pin to a single pod, because the h2c transport "+
						"has no resolver and its connection pool is keyed on the authority. If it spreads "+
						"here, the enabled arm is not measuring the new option.",
						len(idle), len(pods), len(pods)-1)
				}
				return
			}

			if len(idle) > 0 {
				t.Fatalf("with dns_discovery enabled, %d of %d pods received NO traffic: %s.\n"+
					"Every address the Service resolves to should appear in the target list and take a "+
					"share of the requests.", len(idle), len(pods), strings.Join(idle, ", "))
			}

			// Round-robin over a stable set is exact, so an uneven split
			// means the targets came from another list.
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

			// EnsureTransport used to downgrade exactly this case.
			for _, p := range pods {
				for proto, n := range p.protocols() {
					if proto != "HTTP/2.0" {
						t.Errorf("%s (%s) was reached %d time(s) over %q, want HTTP/2.0.\n"+
							"Load-balanced h2c targets must keep their scheme, or the gateway speaks "+
							"HTTP/1.1 to a gRPC server.", p.id, p.ip, n, proto)
					}
				}
			}

			// Dialled by address, addressed by name. A pod IP here breaks
			// anything routing on :authority.
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
