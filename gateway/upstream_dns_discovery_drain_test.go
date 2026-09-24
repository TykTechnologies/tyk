package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/dnsdiscovery"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

func TestUpstreamConnRegistry_LateDialJoinsTheDrain(t *testing.T) {
	r := newUpstreamConnRegistry(nil)
	c1, peer1 := net.Pipe()
	defer peer1.Close()
	tracked1 := r.track("10.0.0.1:9002", c1)
	defer tracked1.Close()
	r.drain("10.0.0.1:9002", 20*time.Millisecond)
	c2, peer2 := net.Pipe()
	defer peer2.Close()
	tracked2 := r.track("10.0.0.1:9002", c2)
	defer tracked2.Close()
	if !closedWithin(t, tracked1, 100*time.Millisecond) {
		t.Fatal("late dial cancelled departure: original connection remains open past the drain deadline")
	}
}
func TestH2CDialler_FallbackConnectionDrainsByAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &dnsDiscoveryPlan{port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(p)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}}
	rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})
	c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "svc:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.1"}})
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.2"}})
	if !closedWithin(t, c, 100*time.Millisecond) {
		t.Fatalf("fallback connection to %s is still open; registry holds it under svc:%s", c.RemoteAddr(), port)
	}
}
func TestSetupUpstreamDNSDiscovery_DeclinedTargetKeepsConfiguredTarget(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.Proxy.TargetURL = "https://svc:8443"
	spec.Proxy.EnableLoadBalancing = true
	spec.Proxy.DNSDiscovery.Enabled = true
	spec.Proxy.StructuredTargetList = apidef.NewHostList()
	result := apidef.Validate(spec.APIDefinition, apidef.ValidationRuleSet{&apidef.RuleDNSDiscovery{}, &apidef.RuleLoadBalancingTargets{}})
	if !result.IsValid {
		t.Fatalf("configuration unexpectedly rejected: %+v", result)
	}
	gw := &Gateway{}
	logger := logrus.NewEntry(logrus.New())
	gw.setupUpstreamDNSDiscovery(spec, logger)
	target, _ := url.Parse(spec.Proxy.TargetURL)
	req, _ := http.NewRequest(http.MethodGet, "http://gateway/", nil)
	proxy := gw.TykNewSingleHostReverseProxy(target, spec, logger)
	proxy.Director(req)
	if req.URL.Host != target.Host {
		resp, err := http.Get(req.URL.String())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("accepted configuration routes to %s instead of configured target %s; HTTP %d: %s", req.URL, target, resp.StatusCode, body)
	}
}
func TestH2CTransport_HealthPingsSpareQuietGRPCStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a stream open for over two minutes against a default gRPC server")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
		if err := stream.SendHeader(metadata.Pairs("review", "8716")); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}))
	go srv.Serve(ln)
	defer srv.Stop()
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(&dnsDiscoveryPlan{})
	var d net.Dialer
	rt := newH2CRoundTripper(spec, &http.Transport{DialContext: d.DialContext}, logrus.NewEntry(logrus.New()), &Gateway{})
	defer rt.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/review.Service/Watch", nil)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	started := time.Now()
	resp, err := rt.h2ctransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if ctx.Err() == nil {
		t.Fatalf("healthy quiet RPC terminated after %s with default server keepalive policy: %v", time.Since(started), err)
	}
}
func TestSetupUpstreamDNSDiscovery_ReloadKeepsPendingDrains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	draining := func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.ConnectionDraining = &apidef.ConnectionDrainingConfig{
			Enabled: true,
			Timeout: tyktime.ReadableDuration(50 * time.Millisecond),
		}
	}
	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, draining)

	var d net.Dialer
	rt := newH2CRoundTripper(spec, &http.Transport{DialContext: d.DialContext}, logrus.NewEntry(logrus.New()), gw)
	c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "127.0.0.1:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resolver.set("svc", "127.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())
	if spec.dnsDiscovery.Load().conns.countFor("127.0.0.1:"+port) != 1 {
		t.Fatal("the connection to the departed backend is not tracked")
	}
	rt.Shutdown()
	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, draining, func(s *APISpec) {
		s.Proxy.PreserveHostHeader = true
	})
	spec.Unload()

	if !closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("reload cancelled the drain: the connection to the departed backend is still open past the drain timeout")
	}
}
func TestH2CDialler_RewrittenUpstreamSurvivesReconciliation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &dnsDiscoveryPlan{host: "svc-a", port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(p)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}}
	rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})
	rewritten := withUpstreamMark(context.Background(), true, false)
	c, err := rt.h2cUnowned.DialTLSContext(rewritten, "tcp", "svc-b:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.1"}})
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.2"}})
	if closedWithin(t, c, 100*time.Millisecond) {
		t.Fatal("connection to svc-b, reached through a URL rewrite, was drained when svc-a's membership changed")
	}
}
func TestH2CDialler_FallbackConnectionToACurrentMemberIsKept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &dnsDiscoveryPlan{port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(p)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}}
	rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})
	c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "svc:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.1"}})
	if closedWithin(t, c, 100*time.Millisecond) {
		t.Fatalf("fallback connection to %s was drained although 127.0.0.1 is in the answer", c.RemoteAddr())
	}
}
func TestH2CDialler_LateFallbackConnectionDrainsWhenTheServiceEmpties(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p := &dnsDiscoveryPlan{port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(p)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}}
	rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})
	p.onAddressSet(&dnsdiscovery.State{Addrs: []string{"127.0.0.1"}})
	c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "svc:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.onAddressSet(&dnsdiscovery.State{Outcome: dnsdiscovery.Empty})
	if !closedWithin(t, c, 100*time.Millisecond) {
		t.Fatalf("fallback connection to %s is still open after the service emptied; registry holds it under svc:%s", c.RemoteAddr(), port)
	}
}
func TestBuildUpstreamTarget_PreservesEscapedPath(t *testing.T) {
	for _, raw := range []string{
		"h2c://svc:9002/tenant%23blue?auth=secret",
		"h2c://svc:9002/tenant%3Fblue?auth=secret",
	} {
		t.Run(raw, func(t *testing.T) {
			target, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			entry := buildUpstreamTarget(target, "10.0.0.1", "9002")
			rendered, err := url.Parse(entry)
			if err != nil {
				t.Fatalf("rendered target %q does not parse: %v", entry, err)
			}
			if rendered.Path != target.Path || rendered.RawQuery != target.RawQuery || rendered.Fragment != "" {
				t.Errorf("rendered %q: path=%q query=%q fragment=%q; want path=%q query=%q and no fragment",
					entry, rendered.Path, rendered.RawQuery, rendered.Fragment, target.Path, target.RawQuery)
			}
		})
	}
}
func TestSetupUpstreamDNSDiscovery_SupersededPlanCannotDrainItsReplacement(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := newStubResolver()
	resolver.set("svc-a", "10.0.0.1")
	resolver.set("svc-b", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)
	ctx := context.Background()
	logger := quietLogger()

	newSpec := func(host string) *APISpec {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		spec.APIID = "api-1"
		spec.Proxy.TargetURL = "h2c://" + host + ":" + port
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.DNSDiscovery.Enabled = true
		spec.Proxy.DNSDiscovery.RefreshInterval = tyktime.ReadableDuration(time.Hour)
		spec.Proxy.DNSDiscovery.ConnectionDraining = &apidef.ConnectionDrainingConfig{
			Enabled: true,
			Timeout: tyktime.ReadableDuration(50 * time.Millisecond),
		}
		return spec
	}

	if _, err := gw.upstreamDNS.Subscribe(ctx, "pin-b", dnsdiscovery.Config{Host: "svc-b"}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var armed bool
	var replacement *APISpec
	var old *APISpec
	var conn net.Conn
	var reloadErr error

	reload := func(*dnsdiscovery.State) {
		mu.Lock()
		defer mu.Unlock()
		if !armed {
			return
		}
		armed = false

		replacement = newSpec("svc-b")
		gw.setupUpstreamDNSDiscovery(replacement, logger)
		old.Unload()

		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			reloadErr = err
			return
		}
		conn = upstreamDrainRegistry(replacement).track("127.0.0.1:"+port, c)
	}
	if _, err := gw.upstreamDNS.Subscribe(ctx, "reloader", dnsdiscovery.Config{Host: "svc-a", OnChange: reload}); err != nil {
		t.Fatal(err)
	}
	gw.upstreamDNS.Refresh(ctx)

	for attempt := 1; attempt <= 64; attempt++ {
		mu.Lock()
		old = newSpec("svc-a")
		gw.setupUpstreamDNSDiscovery(old, logger)
		armed = true
		mu.Unlock()

		resolver.set("svc-a", fmt.Sprintf("10.0.%d.1", attempt))
		gw.upstreamDNS.Refresh(ctx)

		mu.Lock()
		if reloadErr != nil {
			t.Fatal(reloadErr)
		}
		registry := upstreamDrainRegistry(replacement)
		registry.mu.Lock()
		_, pending := registry.drains["127.0.0.1:"+port]
		registry.mu.Unlock()
		conn.Close()
		replacement.Unload()
		mu.Unlock()

		if pending {
			t.Fatalf("attempt %d: a callback for svc-a delivered after api-1 moved to svc-b scheduled a drain of the connection to 127.0.0.1, which svc-b still lists", attempt)
		}
	}
}
func TestSetupUpstreamDNSDiscovery_DisablingDrainingLeavesConnectionsToThePool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.ConnectionDraining = &apidef.ConnectionDrainingConfig{
			Enabled: true,
			Timeout: tyktime.ReadableDuration(50 * time.Millisecond),
		}
	})

	var d net.Dialer
	rt := newH2CRoundTripper(old, &http.Transport{DialContext: d.DialContext}, logrus.NewEntry(logrus.New()), gw)
	c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "127.0.0.1:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if upstreamDrainRegistry(old).countFor("127.0.0.1:"+port) != 1 {
		t.Fatal("the connection to the current backend is not tracked")
	}

	rt.Shutdown()
	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.ConnectionDraining = &apidef.ConnectionDrainingConfig{Enabled: false}
	})
	old.Unload()

	if closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("turning connection draining off closed a connection to 127.0.0.1, which DNS still lists; with draining off it belongs to the pool's idle timeout")
	}
}
func TestUrlFromDNS_ReloadAfterStaleExpiryKeepsServingNoTargets(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	clock := newTestClock()
	gw.upstreamDNS.Now = clock.now

	bounded := func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.StaleTTL = tyktime.ReadableDuration(60 * time.Second)
	}
	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", bounded)

	resolver.fail("svc", errors.New("i/o timeout"))
	clock.advance(120 * time.Second)
	gw.upstreamDNS.Refresh(context.Background())
	if n := mustURLFromDNS(t, gw, old).Len(); n != 0 {
		t.Fatalf("target list holds %d entries past the stale TTL, want none", n)
	}

	reloaded := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002", bounded, func(spec *APISpec) {
		spec.Proxy.PreserveHostHeader = true
	})
	old.Unload()

	list := mustURLFromDNS(t, gw, reloaded)
	if list.Len() != 0 {
		t.Fatalf("an unrelated reload turned the expired name back into %q; before the reload it served no targets", hostAt(t, list, 0))
	}
}
func TestH2CDialler_FallbackDialFinishingAfterTheSweepIsDrained(t *testing.T) {
	cases := []struct {
		name string
		then func(*dnsDiscoveryPlan)
	}{
		{"membership never changes again", func(*dnsDiscoveryPlan) {}},
		{"the service then empties", func(p *dnsDiscoveryPlan) {
			p.onAddressSet(&dnsdiscovery.State{Version: 3, Outcome: dnsdiscovery.Empty})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			_, port, _ := net.SplitHostPort(ln.Addr().String())

			p := &dnsDiscoveryPlan{port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.dnsDiscovery.Store(p)

			connected := make(chan struct{})
			proceed := make(chan struct{})
			transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, network, ln.Addr().String())
				if err != nil {
					return nil, err
				}
				close(connected)
				<-proceed
				return c, nil
			}}
			rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})

			type dialed struct {
				conn net.Conn
				err  error
			}
			result := make(chan dialed, 1)
			go func() {
				c, err := rt.h2ctransport.DialTLSContext(context.Background(), "tcp", "svc:"+port, nil)
				result <- dialed{conn: c, err: err}
			}()

			<-connected
			p.onAddressSet(&dnsdiscovery.State{Version: 2, Addrs: []string{"127.0.0.2"}})
			close(proceed)

			r := <-result
			if r.err != nil {
				t.Fatal(r.err)
			}
			defer r.conn.Close()

			tc.then(p)

			if !closedWithin(t, r.conn, 100*time.Millisecond) {
				t.Fatalf("fallback connection to %s, registered after the sweep, escaped draining although the published set is 127.0.0.2 only", r.conn.RemoteAddr())
			}
		})
	}
}
func TestUpstreamConnRegistry_AbandonKeepsPendingDrainsAndSparesTheRest(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)

	departing, departingPeer := net.Pipe()
	defer departingPeer.Close()
	current, currentPeer := net.Pipe()
	defer currentPeer.Close()

	departed := registry.track("10.0.0.1:9002", departing)
	kept := registry.track("10.0.0.2:9002", current)
	defer kept.Close()
	registry.drain("10.0.0.1:9002", 30*time.Millisecond)
	registry.abandon()

	if !closedWithin(t, departed, 500*time.Millisecond) {
		t.Fatal("abandoning the registry cancelled a pending drain")
	}
	if closedWithin(t, kept, 100*time.Millisecond) {
		t.Fatal("abandoning the registry closed a connection to an address that never departed")
	}

	late, latePeer := net.Pipe()
	defer latePeer.Close()
	defer late.Close()
	registry.track("10.0.0.3:9002", late)
	if got := registry.countFor("10.0.0.3:9002"); got != 0 {
		t.Errorf("an abandoned registry tracked %d new connections", got)
	}
}
func TestH2CTransport_ReusedConnectionKeepsItsOwnership(t *testing.T) {
	cases := []struct {
		name        string
		first       bool
		held        bool
		wantDrained bool
	}{
		{"a discovered stream on a connection a rewrite opened", false, true, true},
		{"a rewritten stream on a connection discovery opened", true, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if r.URL.Path == "/hold" {
					<-r.Context().Done()
				}
			}), &http2.Server{})}
			go srv.Serve(ln)
			defer srv.Close()
			_, port, _ := net.SplitHostPort(ln.Addr().String())

			p := &dnsDiscoveryPlan{port: port, drain: 20 * time.Millisecond, conns: newUpstreamConnRegistry(nil)}
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.dnsDiscovery.Store(p)
			var d net.Dialer
			rt := newH2CRoundTripper(spec, &http.Transport{DialContext: d.DialContext}, logrus.NewEntry(logrus.New()), &Gateway{})
			defer rt.Shutdown()

			base := "http://127.0.0.1:" + port
			p.onAddressSet(&dnsdiscovery.State{Version: 1, Addrs: []string{"127.0.0.1"}})

			opener, err := http.NewRequestWithContext(withUpstreamMark(context.Background(), true, tc.first), http.MethodGet, base+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := rt.h2cFor(opener).RoundTrip(opener)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			ctx, cancel := context.WithTimeout(withUpstreamMark(context.Background(), true, tc.held), 2*time.Second)
			defer cancel()
			stream, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/hold", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err = rt.h2cFor(stream).RoundTrip(stream)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			ended := make(chan struct{})
			go func() {
				io.Copy(io.Discard, resp.Body)
				close(ended)
			}()

			p.onAddressSet(&dnsdiscovery.State{Version: 2, Addrs: []string{"127.0.0.2"}})

			var drained bool
			select {
			case <-ended:
				drained = ctx.Err() == nil
			case <-time.After(300 * time.Millisecond):
			}

			switch {
			case tc.wantDrained && !drained:
				t.Fatal("a discovered stream to 127.0.0.1 outlived the drain after the address left DNS, because it reused a connection a rewrite had dialled")
			case !tc.wantDrained && drained:
				t.Fatal("a rewritten stream was closed when 127.0.0.1 left the discovered set, because it reused a connection discovery had dialled")
			}
		})
	}
}
