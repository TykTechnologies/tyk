package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
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

func selectionContext(sel upstreamSelection) context.Context {
	return context.WithValue(context.Background(), upstreamMarkKey{}, upstreamMark{h2c: true, discovered: true, selection: sel})
}

func listenLocal(t *testing.T) (net.Listener, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ln, port
}

func serveInBackground(t *testing.T, serve func() error) {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- serve() }()
	t.Cleanup(func() {
		err := <-done
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("backend stopped serving: %v", err)
		}
	})
}

func drainingIn(timeout time.Duration) func(*APISpec) {
	return func(spec *APISpec) {
		spec.Proxy.DNSDiscovery.ConnectionDraining = &apidef.ConnectionDrainingConfig{
			Enabled: true,
			Timeout: tyktime.ReadableDuration(timeout),
		}
	}
}

func dialTracked(t *testing.T, spec *APISpec, addr string, sel upstreamSelection) net.Conn {
	t.Helper()

	var d net.Dialer
	rt := newH2CRoundTripper(spec, &http.Transport{}, d.DialContext)
	c, err := rt.h2ctransport.DialTLSContext(selectionContext(sel), "tcp", addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func localPlan(port string, drain time.Duration) *dnsDiscoveryPlan {
	return &dnsDiscoveryPlan{host: "svc", port: port, drain: drain, conns: newUpstreamConnRegistry(nil), generation: 1}
}

func TestUpstreamConnRegistry_LateDialJoinsTheDrain(t *testing.T) {
	r := newUpstreamConnRegistry(nil)
	members(r, 1, 1, 20*time.Millisecond, "10.0.0.1:9002")
	first := trackConn(t, r, "10.0.0.1:9002", upstreamSelection{1, 1})
	members(r, 1, 2, 20*time.Millisecond)
	second := trackConn(t, r, "10.0.0.1:9002", upstreamSelection{1, 1})

	if !closedWithin(t, first, 100*time.Millisecond) || !closedWithin(t, second, 100*time.Millisecond) {
		t.Fatal("a late dial to a departed address did not join its deadline")
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
	target, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://gateway/", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxy := gw.TykNewSingleHostReverseProxy(target, spec, logger)
	proxy.Director(req)
	if req.URL.Host != target.Host {
		t.Fatalf("accepted configuration routes to %s instead of configured target %s", req.URL, target)
	}
}

func TestH2CTransport_HealthPingsSpareQuietGRPCStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a stream open for over two minutes against a default gRPC server")
	}

	ln, _ := listenLocal(t)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ interface{}, stream grpc.ServerStream) error {
		if err := stream.SendHeader(metadata.Pairs("x-stream", "hold")); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}))
	serveInBackground(t, func() error { return srv.Serve(ln) })
	defer srv.Stop()
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(&dnsDiscoveryPlan{})
	var d net.Dialer
	rt := newH2CRoundTripper(spec, &http.Transport{}, d.DialContext)
	defer rt.Retire()
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ln.Addr().String()+"/stream.Service/Watch", nil)
	if err != nil {
		t.Fatal(err)
	}
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
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond))
	c := dialTracked(t, spec, "127.0.0.1:"+port, planSelection(spec))

	resolver.set("svc", "127.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())
	if spec.dnsDiscovery.Load().conns.countFor("127.0.0.1:"+port) != 1 {
		t.Fatal("the connection to the departed backend is not tracked")
	}
	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond), func(s *APISpec) {
		s.Proxy.PreserveHostHeader = true
	})
	spec.Unload()

	if !closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("reload cancelled the drain: the connection to the departed backend is still open past the drain timeout")
	}
}

func TestSetupUpstreamDNSDiscovery_DepartureAfterReloadDrainsOldConnections(t *testing.T) {
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond))
	c := dialTracked(t, old, "127.0.0.1:"+port, planSelection(old))

	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond), func(s *APISpec) {
		s.Proxy.PreserveHostHeader = true
	})
	old.Unload()

	resolver.set("svc", "127.0.0.2")
	gw.upstreamDNS.Refresh(context.Background())

	if !closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("a departure published after the reload left a connection opened before it")
	}
}

func TestSetupUpstreamDNSDiscovery_DepartureWhileNoPlanListensIsDrained(t *testing.T) {
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1", "127.0.0.2")
	gw := newDiscoveryGateway(t, resolver)

	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond))
	c := dialTracked(t, old, "127.0.0.1:"+port, planSelection(old))

	gw.upstreamDNS.ReleaseKey("api-1")
	resolver.set("svc", "127.0.0.2")
	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond))
	old.Unload()

	if !closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("an address that departed between the old plan's last update and the new plan's first was never drained")
	}
}

func TestSetupUpstreamDNSDiscovery_RepointingDrainsTheOldHostname(t *testing.T) {
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc-a", "127.0.0.1")
	resolver.set("svc-b", "127.0.0.2")
	gw := newDiscoveryGateway(t, resolver)

	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc-a:"+port, drainingIn(50*time.Millisecond))
	oldSelection := planSelection(old)
	c := dialTracked(t, old, "127.0.0.1:"+port, oldSelection)

	loadDiscoveredAPI(t, gw, "api-1", "h2c://svc-b:"+port, drainingIn(50*time.Millisecond))
	old.Unload()

	if !closedWithin(t, c, 200*time.Millisecond) {
		t.Fatal("repointing the API left its connection to the previous hostname open")
	}

	var d net.Dialer
	rt := newH2CRoundTripper(old, &http.Transport{}, d.DialContext)
	if _, err := rt.h2ctransport.DialTLSContext(selectionContext(oldSelection), "tcp", "127.0.0.1:"+port, nil); !errors.Is(err, errUpstreamDeparted) {
		t.Fatalf("a dial routed by the superseded plan was accepted after the deadline: %v", err)
	}
}

func TestReleaseUpstreamDNSDiscovery_BoundsARemovedAPI(t *testing.T) {
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	spec := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(80*time.Millisecond))
	sel := planSelection(spec)
	c := dialTracked(t, spec, "127.0.0.1:"+port, sel)

	gw.releaseUpstreamDNSDiscovery(spec)
	spec.Unload()

	if closedWithin(t, c, 30*time.Millisecond) {
		t.Fatal("removing the API cut a connection that still had a request on it")
	}
	if !closedWithin(t, c, time.Second) {
		t.Fatal("a removed API's connection outlived its drain timeout")
	}

	var d net.Dialer
	rt := newH2CRoundTripper(spec, &http.Transport{}, d.DialContext)
	if _, err := rt.h2ctransport.DialTLSContext(selectionContext(sel), "tcp", "127.0.0.1:"+port, nil); !errors.Is(err, errUpstreamDeparted) {
		t.Fatalf("a dial after the removal deadline was accepted: %v", err)
	}
}

func TestH2CDialler_RewrittenUpstreamSurvivesReconciliation(t *testing.T) {
	ln, port := listenLocal(t)
	p := localPlan(port, 20*time.Millisecond)
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	spec.dnsDiscovery.Store(p)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}}
	rt := newH2CRoundTripper(spec, transport, transport.DialContext)
	c, err := rt.h2cUnowned.DialTLSContext(context.Background(), "tcp", "svc-b:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.onAddressSet(&dnsdiscovery.State{Version: 1, Addrs: []string{"127.0.0.1"}})
	p.onAddressSet(&dnsdiscovery.State{Version: 2, Addrs: []string{"127.0.0.2"}})
	if closedWithin(t, c, 100*time.Millisecond) {
		t.Fatal("connection to svc-b, reached through a URL rewrite, was drained when svc's membership changed")
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

func TestSetupUpstreamDNSDiscovery_DisablingDrainingLeavesConnectionsToThePool(t *testing.T) {
	_, port := listenLocal(t)
	resolver := newStubResolver()
	resolver.set("svc", "127.0.0.1")
	gw := newDiscoveryGateway(t, resolver)

	old := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:"+port, drainingIn(50*time.Millisecond))
	c := dialTracked(t, old, "127.0.0.1:"+port, planSelection(old))
	if upstreamDrainRegistry(old).countFor("127.0.0.1:"+port) != 1 {
		t.Fatal("the connection to the current backend is not tracked")
	}

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
	useClock(t, gw, clock)

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

func TestH2CDialler_DialFinishingAfterTheDepartureJoinsTheDeadline(t *testing.T) {
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
			ln, port := listenLocal(t)
			p := localPlan(port, 20*time.Millisecond)
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.dnsDiscovery.Store(p)
			p.onAddressSet(&dnsdiscovery.State{Version: 1, Addrs: []string{"127.0.0.1"}})

			connected := make(chan struct{})
			proceed := make(chan struct{})
			transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, network, ln.Addr().String())
				if err != nil {
					return nil, err
				}
				close(connected)
				<-proceed
				return c, nil
			}}
			rt := newH2CRoundTripper(spec, transport, transport.DialContext)

			type dialed struct {
				conn net.Conn
				err  error
			}
			result := make(chan dialed, 1)
			go func() {
				c, err := rt.h2ctransport.DialTLSContext(selectionContext(upstreamSelection{1, 1}), "tcp", "127.0.0.1:"+port, nil)
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
				t.Fatal("a dial that finished after its address departed escaped the deadline")
			}
		})
	}
}

func TestUpstreamConnRegistry_AbandonKeepsPendingDrainsAndSparesTheRest(t *testing.T) {
	registry := newUpstreamConnRegistry(nil)
	members(registry, 1, 1, 30*time.Millisecond, "10.0.0.1:9002", "10.0.0.2:9002")

	departed := trackConn(t, registry, "10.0.0.1:9002", upstreamSelection{1, 1})
	kept := trackConn(t, registry, "10.0.0.2:9002", upstreamSelection{1, 1})
	members(registry, 1, 2, 30*time.Millisecond, "10.0.0.2:9002")
	registry.abandon()

	if !closedWithin(t, departed, 500*time.Millisecond) {
		t.Fatal("abandoning the registry cancelled a pending drain")
	}
	if closedWithin(t, kept, 100*time.Millisecond) {
		t.Fatal("abandoning the registry closed a connection to an address that never departed")
	}

	late := trackConn(t, registry, "10.0.0.3:9002", upstreamSelection{1, 2})
	defer late.Close()
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
			ln, port := listenLocal(t)
			srv := &http.Server{Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				if r.URL.Path == "/hold" {
					<-r.Context().Done()
				}
			}), &http2.Server{})}
			serveInBackground(t, func() error { return srv.Serve(ln) })
			defer srv.Close()

			p := localPlan(port, 20*time.Millisecond)
			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.dnsDiscovery.Store(p)
			var d net.Dialer
			rt := newH2CRoundTripper(spec, &http.Transport{}, d.DialContext)
			defer rt.Retire()

			base := "http://127.0.0.1:" + port
			p.onAddressSet(&dnsdiscovery.State{Version: 1, Addrs: []string{"127.0.0.1"}})
			markFor := func(discovered bool) upstreamMark {
				return upstreamMark{h2c: true, discovered: discovered, selection: upstreamSelection{1, 1}}
			}
			withMark := func(ctx context.Context, mark upstreamMark) context.Context {
				return context.WithValue(ctx, upstreamMarkKey{}, mark)
			}

			opener, err := http.NewRequestWithContext(withMark(context.Background(), markFor(tc.first)), http.MethodGet, base+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := rt.h2cFor(markFor(tc.first), true).RoundTrip(opener)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			ctx, cancel := context.WithTimeout(withMark(context.Background(), markFor(tc.held)), 2*time.Second)
			defer cancel()
			stream, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/hold", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err = rt.h2cFor(markFor(tc.held), true).RoundTrip(stream)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			ended := make(chan error, 1)
			go func() {
				_, err := io.Copy(io.Discard, resp.Body)
				ended <- err
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
