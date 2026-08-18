package gateway

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
)

// Gate for the gRPC plugin path: dynamic pod discovery.
//
// The counterpart of TestH2C_Upstream_RoundRobin_Distributes, on the other of
// the gateway's two unrelated gRPC paths. Where the upstream path is a plain
// HTTP transport with no resolver at all, this one is a real grpc-go client
// whose round-robin balancing already works — what it never does is notice a
// pod that appeared after the first successful lookup.

const (
	// pluginRefreshInterval is the shortest interval the gateway will accept:
	// config.ResolveDNSRefreshInterval raises anything lower to
	// config.DNSRefreshIntervalMinimum, because the added DNS load is
	// `gateways x APIs / interval` against a shared CoreDNS. These tests
	// therefore have to wait it out rather than dial it down.
	pluginRefreshInterval = int64(10)

	// pluginDiscoveryWait is how long to wait for a scale event to be picked
	// up, with enough margin for the tick that observes it.
	pluginDiscoveryWait = 13 * time.Second
)

// grpcPluginPod is one replica of a gRPC plugin behind a headless Service: a
// dispatcher bound to its own IP, counting the RPCs it serves.
type grpcPluginPod struct {
	coprocess.UnimplementedDispatcherServer

	id   string
	ip   string
	srv  *grpc.Server
	rpcs int64
}

func (p *grpcPluginPod) Dispatch(_ context.Context, obj *coprocess.Object) (*coprocess.Object, error) {
	atomic.AddInt64(&p.rpcs, 1)
	return obj, nil
}

func (p *grpcPluginPod) DispatchEvent(_ context.Context, _ *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}

// startGRPCPluginPods starts n dispatchers, each on its own IP but all sharing
// one port — one name, one port, N pod addresses, which is what a headless
// Service looks like to a client. Returns the pods and the shared port.
func startGRPCPluginPods(t *testing.T, n int) ([]*grpcPluginPod, string) {
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
			"On macOS add a loopback alias first:  sudo ifconfig lo0 alias 127.0.0.2 up\n"+
			"On Linux this always works, so CI gates on this test regardless.",
			n, port, len(listeners), ips)
	}

	pods := make([]*grpcPluginPod, 0, n)
	for i, ln := range listeners {
		pod := &grpcPluginPod{id: fmt.Sprintf("pod-%d", i+1), ip: ips[i]}
		pod.srv = grpc.NewServer()
		coprocess.RegisterDispatcherServer(pod.srv, pod)

		go func(ln net.Listener, srv *grpc.Server) {
			_ = srv.Serve(ln)
		}(ln, pod.srv)
		t.Cleanup(pod.srv.Stop)

		pods = append(pods, pod)
	}

	return pods, port
}

// dispatchN sends n RPCs through the dispatcher and fails on the first error.
func dispatchN(t *testing.T, d coprocess.Dispatcher, n int) {
	t.Helper()

	for i := 0; i < n; i++ {
		if _, err := d.Dispatch(&coprocess.Object{}); err != nil {
			t.Fatalf("dispatch %d/%d failed: %v", i+1, n, err)
		}
	}
}

// TestGRPCPlugin_DNSRefresh_DiscoversNewPods is the gate for the reported
// defect: with round-robin enabled, traffic spreads across the pods that
// existed at boot, and pods created by an autoscaling event never receive any.
//
// The scale-up is the whole test, and the shape of it matters. Nothing is
// restarted and no connection is broken between the two phases, because both
// repair the symptom by accident: a fresh client re-resolves at its first
// dispatch, and a closing connection is one of the two events that make
// grpc-go's stock DNS resolver re-resolve. A harness that restarts the gateway
// mid-run, or that scales down before checking, reports a defect that is not
// there.
//
// Verify scale-up only, in one process, with every connection healthy
// throughout — which is precisely the case in which grpc-go never re-resolves.
func TestGRPCPlugin_DNSRefresh_DiscoversNewPods(t *testing.T) {
	const pluginHost = "grpc-plugin-lb.test"

	pods, port := startGRPCPluginPods(t, 3)

	// Phase 1: two pods are Ready. The rest exist but are not in DNS yet,
	// exactly as a pod that has not been created is not in the Service's
	// endpoint set.
	//
	// Three pods rather than the harness's 2 to 4, because the set has to fit
	// in the distinct local IPv4 addresses a developer machine offers; on Linux
	// the whole of 127.0.0.0/8 is bindable, but macOS assigns only 127.0.0.1
	// unless an operator adds an alias. One added pod is enough: the assertion
	// is that a pod absent at boot receives traffic at all.
	initial := pods[:2]
	added := pods[2:]

	initialIPs := make([]string, 0, len(initial))
	for _, p := range initial {
		initialIPs = append(initialIPs, p.ip)
	}
	dnsMock := mockDomain(t, pluginHost, initialIPs)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.CoProcessOptions.EnableCoProcess = true
		globalConf.CoProcessOptions.CoProcessGRPCServer = fmt.Sprintf("tcp://%s:%s", pluginHost, port)
		globalConf.CoProcessOptions.GRPCRoundRobinLoadBalancing = true
		globalConf.CoProcessOptions.GRPCDNSRefreshInterval = pluginRefreshInterval
	})
	defer ts.Close()

	dispatcher, err := ts.Gw.NewGRPCDispatcher()
	if err != nil {
		t.Fatalf("build gRPC dispatcher: %v", err)
	}
	defer func() {
		if grpcConnection != nil {
			_ = grpcConnection.Close()
		}
	}()

	const baselineRPCs = 40
	dispatchN(t, dispatcher, baselineRPCs)

	// The baseline establishes that per-replica attribution is real. Without
	// it, a zero after the scale-up could just as well be a measurement
	// failure.
	for _, p := range initial {
		if served := atomic.LoadInt64(&p.rpcs); served == 0 {
			t.Fatalf("baseline: %s (%s) served no RPCs of %d, so round-robin is not working even "+
				"before the scale event and nothing below is meaningful", p.id, p.ip, baselineRPCs)
		}
	}
	for _, p := range pods {
		t.Logf("  baseline %s (%s): %d RPCs", p.id, p.ip, atomic.LoadInt64(&p.rpcs))
	}

	// Phase 2: the scale-up. The remaining pods become Ready and DNS starts
	// returning every address. No restart, no scale-down, no broken
	// connection — only the endpoint set changing.
	allIPs := make([]string, 0, len(pods))
	for _, p := range pods {
		allIPs = append(allIPs, p.ip)
	}
	pull := dnsMock.PushDomains(map[string][]string{pluginHost + ".": allIPs}, nil)
	t.Cleanup(pull)
	assertResolves(t, pluginHost, allIPs)

	// Wait out the refresh interval. This is the property under test:
	// discovery latency is bounded by the configured interval, not by a
	// connection failing.
	for _, p := range added {
		atomic.StoreInt64(&p.rpcs, 0)
	}
	time.Sleep(pluginDiscoveryWait)

	const postScaleRPCs = 40
	dispatchN(t, dispatcher, postScaleRPCs)

	for _, p := range pods {
		t.Logf("  after scale-up %s (%s): %d RPCs total", p.id, p.ip, atomic.LoadInt64(&p.rpcs))
	}

	var idle []string
	for _, p := range added {
		if atomic.LoadInt64(&p.rpcs) == 0 {
			idle = append(idle, fmt.Sprintf("%s (%s)", p.id, p.ip))
		}
	}
	if len(idle) > 0 {
		t.Fatalf("%d of %d pods created by the scale event received NO traffic in %d RPCs: %v.\n"+
			"DNS returned all %d addresses. Every existing connection stayed healthy, so nothing "+
			"called ResolveNow and the new addresses were never learned — which is the reported "+
			"defect: the gateway keeps serving the pods it saw at boot.",
			len(idle), len(added), postScaleRPCs, idle, len(allIPs))
	}
}

// TestGRPCPlugin_DNSRefresh_Disabled is the control. With the refresh interval
// negative, polling is off and the client is left with grpc-go's stock
// behaviour, which does not notice the scale-up. If this ever passes, the test
// above is not measuring what it claims to.
func TestGRPCPlugin_DNSRefresh_Disabled(t *testing.T) {
	const (
		pluginHost = "grpc-plugin-nolb.test"
		requests   = 40
	)

	pods, port := startGRPCPluginPods(t, 3)
	initial, added := pods[:2], pods[2:]

	initialIPs := make([]string, 0, len(initial))
	for _, p := range initial {
		initialIPs = append(initialIPs, p.ip)
	}
	dnsMock := mockDomain(t, pluginHost, initialIPs)

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.CoProcessOptions.EnableCoProcess = true
		globalConf.CoProcessOptions.CoProcessGRPCServer = fmt.Sprintf("tcp://%s:%s", pluginHost, port)
		globalConf.CoProcessOptions.GRPCRoundRobinLoadBalancing = true
		globalConf.CoProcessOptions.GRPCDNSRefreshInterval = -1 // polling off
	})
	defer ts.Close()

	dispatcher, err := ts.Gw.NewGRPCDispatcher()
	if err != nil {
		t.Fatalf("build gRPC dispatcher: %v", err)
	}
	defer func() {
		if grpcConnection != nil {
			_ = grpcConnection.Close()
		}
	}()

	dispatchN(t, dispatcher, requests)

	allIPs := make([]string, 0, len(pods))
	for _, p := range pods {
		allIPs = append(allIPs, p.ip)
	}
	pull := dnsMock.PushDomains(map[string][]string{pluginHost + ".": allIPs}, nil)
	t.Cleanup(pull)
	assertResolves(t, pluginHost, allIPs)

	for _, p := range added {
		atomic.StoreInt64(&p.rpcs, 0)
	}
	// Wait as long as the discovery arm does, so the two are comparable: a
	// control that simply waited less would prove nothing.
	time.Sleep(pluginDiscoveryWait)
	dispatchN(t, dispatcher, requests)

	for _, p := range added {
		if served := atomic.LoadInt64(&p.rpcs); served != 0 {
			t.Errorf("control: with grpc_dns_refresh_interval disabled, %s (%s) served %d RPCs after "+
				"the scale event. Nothing should have re-resolved, so the pod should have stayed idle; "+
				"if it did receive traffic, something other than the poller is discovering pods and the "+
				"discovery test proves nothing.", p.id, p.ip, served)
		}
	}
}
