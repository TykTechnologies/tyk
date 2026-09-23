package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/TykTechnologies/tyk/apidef"
)

// The request tracer builds a spec from the posted definition and runs it
// through processSpec. That spec carries the live APIID, and MakeSpec returns
// the live *APISpec outright when the checksum matches, so reconciling DNS
// discovery from it would release or supersede the running API's subscription.
func TestProcessSpecWithoutUpstreamDNSDiscovery(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	gw := newDiscoveryGateway(t, resolver)
	live := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

	before, err := gw.urlFromDNS(live)
	if err != nil {
		t.Fatal(err)
	}

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

	// A traced definition carrying the same APIID that does not qualify for
	// discovery. Without the opt-out this releases the live subscription.
	traced := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	traced.APIID = "api-1"
	traced.Proxy.TargetURL = "h2c://svc:9002"
	traced.Proxy.EnableLoadBalancing = false
	traced.Proxy.DNSDiscovery.Enabled = true

	var options = ProcessSpecOptions{}
	WithoutUpstreamDNSDiscovery()(&options)
	if !options.skipUpstreamDNSDiscovery {
		t.Fatal("WithoutUpstreamDNSDiscovery did not set the flag")
	}
	if !options.skipUpstreamDNSDiscovery {
		gw.setupUpstreamDNSDiscovery(traced, logger)
	}

	// The live API must still be resolving its hostname.
	lookupsBefore := gw.upstreamDNS.Lookups()
	resolver.set("svc", "10.0.0.3")
	gw.upstreamDNS.Refresh(context.Background())

	if gw.upstreamDNS.Lookups() == lookupsBefore {
		t.Fatal("the live API's hostname is no longer being resolved")
	}

	after, err := gw.urlFromDNS(live)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.All()) != 1 || after.All()[0] != "h2c://10.0.0.3:9002" {
		t.Fatalf("live API did not follow the address change: before %v, after %v", before.All(), after.All())
	}
}

// http2.Transport has no DisableKeepAlives of its own, so closing idle
// connections is all the library offers and an in-flight request through a
// retired transport would otherwise just dial a fresh one.
func TestShutdownStopsNewH2CConnections(t *testing.T) {
	var dials atomic.Int64

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	backend := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), &http2.Server{}),
	}
	go func() {
		if err := backend.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("backend serve: %v", err)
		}
	}()
	defer backend.Close()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	rt := newH2CRoundTripper(spec, transport, logrus.NewEntry(logrus.New()), &Gateway{})

	do := func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		if err != nil {
			return err
		}

		resp, err := rt.h2ctransport.RoundTrip(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	if err := do(); err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("expected one dial, got %d", dials.Load())
	}

	rt.Shutdown()

	if err := do(); !errors.Is(err, errTransportRetired) {
		t.Fatalf("request through a retired transport returned %v, want %v", err, errTransportRetired)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("a retired transport dialled again: %d dials, want 1", got)
	}
}

// A rebuild replaces the transport while requests are still holding the old one
// (WrappedServeHTTP retires it once MaxConnTime has passed). Those requests have
// to finish, so Retire must not stop the dialler the way Shutdown does.
func TestRetireLetsInFlightH2CRequestsFinish(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	backend := &http.Server{
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), &http2.Server{}),
	}
	go func() {
		if err := backend.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("backend serve: %v", err)
		}
	}()
	defer backend.Close()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	rt := newH2CRoundTripper(spec, &http.Transport{}, logrus.NewEntry(logrus.New()), &Gateway{})

	do := func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/", nil)
		if err != nil {
			return err
		}

		resp, err := rt.h2ctransport.RoundTrip(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}

	if err := do(); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// The rebuild path, which must leave the dialler open.
	rt.Retire()

	if err := do(); err != nil {
		t.Fatalf("a request through a retired-but-not-shut-down transport failed: %v.\n"+
			"A transport replaced by a MaxConnTime rebuild still has requests on it; "+
			"they must be able to dial rather than get errTransportRetired.", err)
	}
}
