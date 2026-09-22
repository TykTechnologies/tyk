package gateway

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	pbexample "google.golang.org/grpc/examples/helloworld/helloworld"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// A real gRPC server and client either side of the gateway, rather than
// r.Proto against a plain h2c handler. A real server speaks HTTP/2 and nothing
// else, so a downgraded target fails the RPC rather than slowing it.

// Reports its identity in every reply, and records the :authority.
type grpcPod struct {
	id   string
	ip   string
	port string
	srv  *grpc.Server
	hits int64

	mu          sync.Mutex
	authorities map[string]int
}

func (p *grpcPod) target() string { return "h2c://" + net.JoinHostPort(p.ip, p.port) }

func (p *grpcPod) bareTarget() string { return net.JoinHostPort(p.ip, p.port) }

func (p *grpcPod) authorityList() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make(map[string]int, len(p.authorities))
	for a, n := range p.authorities {
		out[a] = n
	}
	return out
}

type podGreeter struct {
	pbexample.UnimplementedGreeterServer
	pod *grpcPod
}

func (g *podGreeter) SayHello(ctx context.Context, _ *pbexample.HelloRequest) (*pbexample.HelloReply, error) {
	atomic.AddInt64(&g.pod.hits, 1)

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if a := md.Get(":authority"); len(a) > 0 {
			g.pod.mu.Lock()
			g.pod.authorities[a[0]]++
			g.pod.mu.Unlock()
		}
	}

	return &pbexample.HelloReply{Message: g.pod.id}, nil
}

// startGRPCPodSet is startH2CPodSet with real gRPC servers.
func startGRPCPodSet(t *testing.T, n int) ([]*grpcPod, string) {
	t.Helper()

	candidates := podAddrCandidates()

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
			"On macOS add loopback aliases first:  sudo ifconfig lo0 alias 127.0.0.2 up\n"+
			"On Linux this always works, so CI gates on this test regardless.",
			n, port, len(listeners), ips)
	}

	pods := make([]*grpcPod, 0, n)
	for i, ln := range listeners {
		pod := &grpcPod{
			id:          fmt.Sprintf("pod-%d", i+1),
			ip:          ips[i],
			port:        port,
			authorities: map[string]int{},
		}

		pod.srv = grpc.NewServer()
		pbexample.RegisterGreeterServer(pod.srv, &podGreeter{pod: pod})

		go func(ln net.Listener, srv *grpc.Server) {
			if err := srv.Serve(ln); err != nil {
				t.Logf("pod server stopped: %v", err)
			}
		}(ln, pod.srv)

		t.Cleanup(pod.srv.Stop)
		pods = append(pods, pod)
	}

	return pods, port
}

func resetPods(pods []*grpcPod) {
	for _, p := range pods {
		atomic.StoreInt64(&p.hits, 0)
		p.mu.Lock()
		p.authorities = map[string]int{}
		p.mu.Unlock()
	}
}

// The default listener wraps its handler in h2c, so a gRPC client can dial
// it.
func gatewayHostPort(t *testing.T, ts *Test) string {
	t.Helper()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse gateway URL %q: %v", ts.URL, err)
	}
	return u.Host
}

// A custom ListenPort's listener is created while the API loads, so calls
// sent straight after BuildAndLoadAPI can sit until their own deadline. Any
// answer counts, including a proxying error.
func waitForGRPCGateway(t *testing.T, gatewayAddr string, pods []*grpcPod) {
	t.Helper()

	conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	client := pbexample.NewGreeterClient(conn)

	deadline := time.Now().Add(60 * time.Second)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := client.SayHello(ctx, &pbexample.HelloRequest{Name: "warmup"})
		cancel()

		code := status.Code(err)
		if err == nil || (code != codes.DeadlineExceeded && code != codes.Unavailable) {
			t.Logf("  gateway answered on attempt %d (%v)", attempt, code)
			resetPods(pods)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatalf("gateway at %s did not answer within 60s", gatewayAddr)
}

// Groups replies by pod. An RPC error does not fail the test, since one arm
// expects every call to fail.
func callGreeter(t *testing.T, gatewayAddr string, n int) (map[string]int, error) {
	t.Helper()

	conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	defer conn.Close()

	client := pbexample.NewGreeterClient(conn)
	served := map[string]int{}

	var firstErr error
	var failed int
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		started := time.Now()
		reply, err := client.SayHello(ctx, &pbexample.HelloRequest{Name: "spike"})
		cancel()

		if err != nil {
			// Only the first few, or an all-failing arm buries the verdict.
			if failed < 3 {
				t.Logf("    call %2d failed after %s: %v", i, time.Since(started).Round(time.Millisecond), err)
			}
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		served[reply.Message]++
	}

	if failed > 3 {
		t.Logf("    ... and %d more failures, all alike", failed-3)
	}

	return served, firstErr
}

func evenness(served map[string]int, pods int) float64 {
	if pods == 0 || len(served) == 0 {
		return 0
	}

	total, highest := 0, 0
	for _, n := range served {
		total += n
		if n > highest {
			highest = n
		}
	}
	mean := float64(total) / float64(pods)
	if mean == 0 {
		return 0
	}
	return float64(highest) / mean
}

func totalServed(served map[string]int) int {
	total := 0
	for _, n := range served {
		total += n
	}
	return total
}

func logGRPCPods(t *testing.T, pods []*grpcPod) {
	t.Helper()

	for _, p := range pods {
		t.Logf("  %s (%s): %d calls served, authorities %v",
			p.id, p.bareTarget(), atomic.LoadInt64(&p.hits), p.authorityList())
	}
}

func idleGRPCPods(pods []*grpcPod) []string {
	var idle []string
	for _, p := range pods {
		if atomic.LoadInt64(&p.hits) == 0 {
			idle = append(idle, fmt.Sprintf("%s (%s)", p.id, p.bareTarget()))
		}
	}
	return idle
}

// assertDowngradedArmFails checks the control arm still fails outright, which is
// what makes the passing arm evidence of anything.
func assertDowngradedArmFails(t *testing.T, reason string, total, requests int, callErr error) {
	t.Helper()

	if callErr == nil && total == requests {
		t.Fatalf("every call succeeded, but this arm is expected to fail: %s.\n"+
			"If the gateway now reaches a gRPC upstream over a load-balanced entry "+
			"written without a scheme, the coalescing described above has changed and "+
			"the service discovery limitation recorded in TT-18059 no longer holds.",
			reason)
	}
	if total > 0 {
		t.Errorf("%d of %d calls were answered on an arm expected to fail outright; "+
			"the downgrade is expected to break every call, not some of them", total, requests)
	}
}

func assertAllCallsAnswered(t *testing.T, total, requests int, callErr error) {
	t.Helper()

	if callErr != nil {
		t.Fatalf("%d/%d calls answered, first error %v.\n"+
			"Load balancing over explicit h2c:// targets must reach a real gRPC server. "+
			"An error here means the target list is being rewritten to http:// again and "+
			"the gateway is offering HTTP/1.1 to an HTTP/2-only server.", total, requests, callErr)
	}
	if total != requests {
		t.Fatalf("%d of %d calls answered and no error was returned, which should not happen",
			total, requests)
	}
}

// The arms differ only in how the target list spells its entries, which is the
// whole of the h2c load balancing defect. Target selection prepends the listen
// protocol to an entry with no scheme, coalescing an inherited h2c to http.
//
//   - explicit_h2c_targets: entries carry h2c:// of their own, and succeed.
//   - inherited_scheme_targets: bare host:port, still downgraded. A registry
//     returns exactly this shape, which is why service discovery cannot
//     deliver a cleartext HTTP/2 target.
func TestGRPCUpstream_StaticLB_RealGRPC(t *testing.T) {
	const requests = 20

	pods, port := startGRPCPodSet(t, 2)
	t.Logf("pod set on port %s: %s, %s", port, pods[0].bareTarget(), pods[1].bareTarget())

	for _, arm := range []struct {
		name       string
		targets    []string
		wantCalls  bool
		wantReason string
	}{
		{
			name:      "explicit_h2c_targets",
			targets:   []string{pods[0].target(), pods[1].target()},
			wantCalls: true,
		},
		{
			name:       "inherited_scheme_targets",
			targets:    []string{pods[0].bareTarget(), pods[1].bareTarget()},
			wantCalls:  false,
			wantReason: "an entry with no scheme inherits the API's listen protocol and an inherited h2c is coalesced to http",
		},
	} {
		t.Run(arm.name, func(t *testing.T) {
			resetPods(pods)

			ts := StartTest(nil)
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Name = "grpc-static-lb-" + arm.name
				spec.Proxy.ListenPath = "/"
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = pods[0].target()
				spec.Proxy.EnableLoadBalancing = true
				spec.Proxy.Targets = arm.targets
			})

			gatewayAddr := gatewayHostPort(t, ts)
			waitForGRPCGateway(t, gatewayAddr, pods)

			served, callErr := callGreeter(t, gatewayAddr, requests)
			total := totalServed(served)

			logGRPCPods(t, pods)
			t.Logf("  %d/%d calls answered, first error: %v", total, requests, callErr)

			if !arm.wantCalls {
				assertDowngradedArmFails(t, arm.wantReason, total, requests, callErr)
				return
			}

			assertAllCallsAnswered(t, total, requests, callErr)

			if idle := idleGRPCPods(pods); len(idle) > 0 {
				t.Fatalf("load balancing is enabled over %d targets but %v received no calls; "+
					"requests are not being distributed", len(arm.targets), idle)
			}

			if got := evenness(served, len(pods)); got > 1.5 {
				t.Errorf("distribution evenness %.2f exceeds the 1.5 bar, counts %v", got, served)
			}
		})
	}
}

// assertPodAuthority checks every pod was told the configured authority. A gRPC
// server doing virtual hosting rejects anything else.
func assertPodAuthority(t *testing.T, pods []*grpcPod, want string) {
	t.Helper()

	for _, p := range pods {
		auths := p.authorityList()
		if auths[want] == 0 {
			t.Errorf("%s saw authorities %v, none of them %q. Dialling the pod address "+
				"must not change the authority the upstream is told.",
				p.id, auths, want)
		}
	}
}

// assertPinnedToOneGRPCPod is the control arm: without discovery the cleartext
// HTTP/2 client has no resolver and pools by the host in the request URL.
func assertPinnedToOneGRPCPod(t *testing.T, pods []*grpcPod, idle []string) {
	t.Helper()

	if len(idle) != len(pods)-1 {
		t.Errorf("control: with DNS discovery off, %d of %d pods were idle, want %d. "+
			"Traffic is expected to pin to one pod, because the cleartext HTTP/2 client "+
			"has no resolver and pools by the host in the request URL. If it spreads "+
			"here, the enabled arm is not measuring the setting.",
			len(idle), len(pods), len(pods)-1)
	}
}

// Configured as the reported case is: one upstream name, no target list. The
// calls only succeed if the resolved addresses enter the target list, keep the
// h2c scheme, and keep the service name as their authority, so all three are
// asserted together. The disabled arm is the control, and pins to one pod.
func TestGRPCUpstream_DNSDiscovery_RealGRPC(t *testing.T) {
	const (
		upstreamHost    = "grpc-real-lb.test"
		requests        = 30
		dnsCacheTimeout = 10
	)

	pods, port := startGRPCPodSet(t, 2)

	ips := make([]string, 0, len(pods))
	for _, p := range pods {
		ips = append(ips, p.ip)
	}
	mockDomain(t, upstreamHost, ips)
	t.Logf("%s:%s resolves to %v (a %d-pod headless Service of real gRPC servers)",
		upstreamHost, port, ips, len(ips))

	wantAuthority := net.JoinHostPort(upstreamHost, port)

	cases := []struct {
		name    string
		enabled bool
	}{
		{"dns_discovery_enabled", true},
		{"dns_discovery_disabled", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetPods(pods)

			ts := StartTest(nil)
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Name = "grpc-dns-lb-" + tc.name
				spec.Proxy.ListenPath = "/"
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
				spec.Proxy.EnableLoadBalancing = tc.enabled
				spec.Proxy.DNSDiscovery.Enabled = tc.enabled
				spec.Proxy.DNSDiscovery.RefreshInterval = dnsCacheTimeout
			})

			gatewayAddr := gatewayHostPort(t, ts)
			waitForGRPCGateway(t, gatewayAddr, pods)

			served, callErr := callGreeter(t, gatewayAddr, requests)
			total := totalServed(served)
			idle := idleGRPCPods(pods)
			logGRPCPods(t, pods)

			if callErr != nil {
				t.Fatalf("%d/%d calls answered, first error %v.\n"+
					"The calls have to succeed before distribution means anything: a resolved "+
					"address written into the target list without its h2c scheme, or dialled "+
					"without the configured authority, fails at the gRPC server.",
					total, requests, callErr)
			}
			if total != requests {
				t.Fatalf("pods answered %d of %d calls with no error returned", total, requests)
			}

			if !tc.enabled {
				assertPinnedToOneGRPCPod(t, pods, idle)
				return
			}

			if len(idle) > 0 {
				t.Fatalf("with DNS discovery on, %v received no calls; every address the Service "+
					"resolves to should take a share of the requests", idle)
			}

			if got := evenness(served, len(pods)); got > 1.5 {
				t.Errorf("distribution evenness %.2f exceeds the 1.5 bar, counts %v", got, served)
			}

			assertPodAuthority(t, pods, wantAuthority)
		})
	}
}

// The defect the parent ticket exists for. A second address is added to the
// name with no connection broken and no API reloaded, and the new pod has to
// appear within the refresh interval.
func TestGRPCUpstream_DNSDiscovery_ScaleUp(t *testing.T) {
	const (
		upstreamHost    = "grpc-real-scaleup.test"
		refreshInterval = 5
		requests        = 20
	)

	pods, port := startGRPCPodSet(t, 2)
	before, added := pods[0], pods[1]

	// Membership at boot.
	handle := mockDomain(t, upstreamHost, []string{before.ip})

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "grpc-dns-lb-scaleup"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.DNSDiscovery.Enabled = true
		spec.Proxy.DNSDiscovery.RefreshInterval = refreshInterval
	})

	gatewayAddr := gatewayHostPort(t, ts)
	waitForGRPCGateway(t, gatewayAddr, pods)

	served, callErr := callGreeter(t, gatewayAddr, requests)
	if callErr != nil {
		t.Fatalf("calls failed before the scale event: %v (served %v)", callErr, served)
	}
	if atomic.LoadInt64(&added.hits) != 0 {
		t.Fatalf("%s served calls before it was added to the Service, so this test cannot "+
			"attribute discovery to the scale event", added.id)
	}
	t.Logf("before the scale event: %v", served)

	// The scale event. Same name, one more address.
	pull := handle.PushDomains(map[string][]string{
		upstreamHost + ".": {before.ip, added.ip},
	}, nil)
	t.Cleanup(pull)
	assertResolves(t, upstreamHost, []string{before.ip, added.ip})

	resetPods(pods)

	// The polling calls are incidental; the refresh is in the background.
	deadline := time.Now().Add((refreshInterval + 15) * time.Second)
	var discovered bool
	for time.Now().Before(deadline) {
		if _, err := callGreeter(t, gatewayAddr, 4); err != nil {
			t.Fatalf("calls failed after the scale event: %v", err)
		}
		if atomic.LoadInt64(&added.hits) > 0 {
			discovered = true
			break
		}
		time.Sleep(time.Second)
	}

	for _, p := range pods {
		t.Logf("  %s (%s): %d calls served after the scale event", p.id, p.bareTarget(), atomic.LoadInt64(&p.hits))
	}

	if !discovered {
		t.Fatalf("%s (%s) received no calls within %d seconds of being added to %s.\n"+
			"A pod created by an autoscaling event has to start receiving traffic within the "+
			"refresh interval, without a connection failure to prompt rediscovery.",
			added.id, added.bareTarget(), refreshInterval+15, upstreamHost)
	}
}
