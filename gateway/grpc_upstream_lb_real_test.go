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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pbexample "google.golang.org/grpc/examples/helloworld/helloworld"
)

// The tests in this file answer two questions with a real gRPC server and a
// real gRPC client on either side of the gateway, rather than by asserting on
// r.Proto against a plain h2c handler as grpc_h2c_defects_test.go does:
//
//   1. Is load balancing broken for h2c? A protocol downgrade is only a defect
//      if it actually fails. A real gRPC server speaks HTTP/2 and nothing else,
//      so a downgraded target produces a failed RPC rather than a slower one.
//
//   2. Does DNS discovery work for real gRPC? Distribution of HTTP/2 requests
//      is necessary but not sufficient: the resolved addresses have to keep the
//      h2c scheme and the configured authority, or the calls fail on arrival.
//
// Both are measured in the same run, against the same pod set.

// grpcPod is one backend replica in a simulated headless Service: a real gRPC
// server bound to its own loopback address, reporting its identity in every
// reply so the caller can attribute traffic, and recording the :authority it
// was addressed with.
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

// podGreeter answers SayHello with the pod's identity.
type podGreeter struct {
	pbexample.UnimplementedGreeterServer
	pod *grpcPod
}

func (g *podGreeter) SayHello(ctx context.Context, in *pbexample.HelloRequest) (*pbexample.HelloReply, error) {
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

// startGRPCPodSet starts n real gRPC servers, each on its own local address but
// all on the SAME port, which is what a headless Service looks like to a
// client: one name, one port, N pod addresses.
//
// Port selection mirrors startH2CPodSet: claim a port on the first candidate
// address, then hold every listener open so nothing can take the port on the
// others underneath the set.
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

// resetPods clears the counters so one pod set can serve several arms.
func resetPods(pods []*grpcPod) {
	for _, p := range pods {
		atomic.StoreInt64(&p.hits, 0)
		p.mu.Lock()
		p.authorities = map[string]int{}
		p.mu.Unlock()
	}
}

// gatewayHostPort returns the host:port a real gRPC client should dial for the
// gateway's default listener. That listener wraps its handler in h2c, so a
// cleartext gRPC client reaches it without a dedicated port being whitelisted.
func gatewayHostPort(t *testing.T, ts *Test) string {
	t.Helper()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse gateway URL %q: %v", ts.URL, err)
	}
	return u.Host
}

// waitForGRPCGateway blocks until the gateway answers on its h2c listener,
// then leaves the pod counters clean.
//
// The listener for a custom ListenPort is created while the API loads, so the
// first calls after BuildAndLoadAPI can be sent before anything is listening
// and sit until their own deadline. Waiting for a definitive answer keeps that
// start-up window out of the measurement. Any answer counts, including a
// proxying error: an arm expecting every call to fail still needs the gateway
// to be up before the failures mean anything.
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

// callGreeter makes n unary calls through the gateway on one client connection
// and returns the replies grouped by the pod that answered, plus the first
// error seen. It does not fail the test on an RPC error, because one of the
// tests below expects every call to fail.
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
			// Only the first few, so an arm where every call is expected to
			// fail does not bury the verdict in identical lines.
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

// evenness reports max/mean over the served counts, the same bar the TT-17922
// reproduction harness scores distribution against.
func evenness(served map[string]int, pods int) float64 {
	if pods == 0 || len(served) == 0 {
		return 0
	}

	total, max := 0, 0
	for _, n := range served {
		total += n
		if n > max {
			max = n
		}
	}
	mean := float64(total) / float64(pods)
	if mean == 0 {
		return 0
	}
	return float64(max) / mean
}

// TestGRPCUpstream_StaticLB_RealGRPC measures whether load balancing works for
// a cleartext gRPC upstream, using a real gRPC client and two real gRPC servers.
//
// The two arms differ only in how the target list spells its entries, and that
// difference is the whole of the h2c load-balancing defect. Target selection
// runs before the transport is chosen, and it prepends the API's listen
// protocol to any entry that has no scheme of its own, coalescing an inherited
// h2c to http. The transport is then chosen from the scheme on the outgoing
// request, which by then says http, so the gateway offers HTTP/1.1 to a server
// that speaks HTTP/2 and nothing else.
//
//   - explicit_h2c_targets: every entry carries h2c:// of its own. Calls
//     succeed and are distributed. Before TT-17922 narrowed the rewrite, the
//     scheme was replaced unconditionally and this arm failed the same way the
//     second one does.
//   - inherited_scheme_targets: entries are bare host:port. Still downgraded
//     today, which is why service discovery cannot currently deliver a
//     cleartext HTTP/2 target: a registry returning host and port values
//     produces exactly this shape.
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

			total := 0
			for _, n := range served {
				total += n
			}
			for _, p := range pods {
				t.Logf("  %s (%s): %d calls served, authorities %v",
					p.id, p.bareTarget(), atomic.LoadInt64(&p.hits), p.authorityList())
			}
			t.Logf("  %d/%d calls answered, first error: %v", total, requests, callErr)

			if !arm.wantCalls {
				if callErr == nil && total == requests {
					t.Fatalf("every call succeeded, but this arm is expected to fail: %s.\n"+
						"If the gateway now reaches a gRPC upstream over a load-balanced entry "+
						"written without a scheme, the coalescing described above has changed and "+
						"the service discovery limitation recorded in TT-18059 no longer holds.",
						arm.wantReason)
				}
				if total > 0 {
					t.Errorf("%d of %d calls were answered on an arm expected to fail outright; "+
						"the downgrade is expected to break every call, not some of them", total, requests)
				}
				return
			}

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

			var idle []string
			for _, p := range pods {
				if atomic.LoadInt64(&p.hits) == 0 {
					idle = append(idle, fmt.Sprintf("%s (%s)", p.id, p.bareTarget()))
				}
			}
			if len(idle) > 0 {
				t.Fatalf("load balancing is enabled over %d targets but %v received no calls; "+
					"requests are not being distributed", len(arm.targets), idle)
			}

			if got := evenness(served, len(pods)); got > 1.5 {
				t.Errorf("distribution evenness %.2f exceeds the 1.5 bar, counts %v", got, served)
			}
		})
	}
}

// TestGRPCUpstream_DNSDiscovery_RealGRPC measures whether DNS discovery
// delivers working gRPC, not merely distributed HTTP/2.
//
// The API is configured the way the reported case is: one upstream name, no
// target list. The name resolves to every pod address, as a headless Service
// does. Three things have to hold together for the calls to succeed at all,
// which is why they are asserted in one test: the resolved addresses have to
// enter the target list, they have to keep the h2c scheme so the cleartext
// HTTP/2 transport is selected, and each request has to keep the configured
// service name as its authority so the pod sees the Host it expects.
//
// The disabled arm is the control. Without the setting the traffic pins to one
// pod, which is the behaviour on the released gateway.
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

	for _, enabled := range []bool{true, false} {
		name := "dns_discovery_disabled"
		if enabled {
			name = "dns_discovery_enabled"
		}

		t.Run(name, func(t *testing.T) {
			resetPods(pods)

			ts := StartTest(nil)
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Name = "grpc-dns-lb-" + name
				spec.Proxy.ListenPath = "/"
				spec.UseKeylessAccess = true
				spec.Proxy.TargetURL = fmt.Sprintf("h2c://%s:%s", upstreamHost, port)
				// DNS discovery supplies the target list;
				// enable_load_balancing distributes it. Both go on together,
				// and the control arm has neither.
				spec.Proxy.EnableLoadBalancing = enabled
				spec.Proxy.DNSDiscovery.Enabled = enabled
				spec.Proxy.DNSDiscovery.RefreshInterval = dnsCacheTimeout
			})

			gatewayAddr := gatewayHostPort(t, ts)
			waitForGRPCGateway(t, gatewayAddr, pods)

			served, callErr := callGreeter(t, gatewayAddr, requests)

			total := 0
			for _, n := range served {
				total += n
			}
			var idle []string
			for _, p := range pods {
				if atomic.LoadInt64(&p.hits) == 0 {
					idle = append(idle, fmt.Sprintf("%s (%s)", p.id, p.bareTarget()))
				}
				t.Logf("  %s (%s:%s): %d calls served, authorities %v",
					p.id, p.ip, port, atomic.LoadInt64(&p.hits), p.authorityList())
			}

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

			if !enabled {
				if len(idle) != len(pods)-1 {
					t.Errorf("control: with DNS discovery off, %d of %d pods were idle, want %d. "+
						"Traffic is expected to pin to one pod, because the cleartext HTTP/2 client "+
						"has no resolver and pools by the host in the request URL. If it spreads "+
						"here, the enabled arm is not measuring the setting.",
						len(idle), len(pods), len(pods)-1)
				}
				return
			}

			if len(idle) > 0 {
				t.Fatalf("with DNS discovery on, %v received no calls; every address the Service "+
					"resolves to should take a share of the requests", idle)
			}

			if got := evenness(served, len(pods)); got > 1.5 {
				t.Errorf("distribution evenness %.2f exceeds the 1.5 bar, counts %v", got, served)
			}

			// The pods are addressed individually but must still be told the
			// service name, or a gRPC server doing virtual hosting rejects them.
			for _, p := range pods {
				auths := p.authorityList()
				if n := auths[wantAuthority]; n == 0 {
					t.Errorf("%s saw authorities %v, none of them %q. Dialling the pod address "+
						"must not change the authority the upstream is told.",
						p.id, auths, wantAuthority)
				}
			}
		})
	}
}

// TestGRPCUpstream_DNSDiscovery_ScaleUp measures the defect the parent ticket
// exists for: a pod created by an autoscaling event has to start receiving
// calls without a connection failing first.
//
// The Service starts with one address, so the first arm of calls has only one
// place to go. A second address is then added to the name, as a scale-up does,
// and nothing is disturbed: no connection is broken, no API is reloaded. The
// new pod has to appear within the refresh interval on its own.
func TestGRPCUpstream_DNSDiscovery_ScaleUp(t *testing.T) {
	const (
		upstreamHost    = "grpc-real-scaleup.test"
		refreshInterval = 5
		requests        = 20
	)

	pods, port := startGRPCPodSet(t, 2)
	before, added := pods[0], pods[1]

	// Membership at boot: one pod.
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

	// Poll until the new pod is reached, bounded by the refresh interval with
	// margin. The calls made while polling are incidental: the scheduler
	// refreshes in the background, so the pod would be discovered with no
	// traffic at all. TestScheduler_DiscoversWithoutTraffic asserts that
	// directly. The traffic itself does nothing to
	// trigger rediscovery: no connection is closed and every call succeeds
	// whichever pod answers, which is exactly why the released gateway never
	// notices a scale-up.
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
