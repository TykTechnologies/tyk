package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/test"
)

func TestDNSDiscovery_EmptyServiceAnswersNoHealthyUpstreams(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.upstreamDNS.Lookup = func(context.Context, string) ([]string, error) { return nil, nil }
	ts.Gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "dns-empty"
		spec.Proxy.ListenPath = "/dns-empty/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = "h2c://svc.example:9002"
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.DNSDiscovery.Enabled = true
	})

	_, _ = ts.Run(t, test.TestCase{
		Path:      "/dns-empty/",
		Code:      http.StatusServiceUnavailable,
		BodyMatch: "all hosts are down",
	})
}

func TestH2CRoundTripper_HTTPTargetOnAnH2COnlyAPIUsesHTTP1(t *testing.T) {
	var proto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	spec := &APISpec{}
	rt := newH2CRoundTripper(spec, &http.Transport{})
	rt.h2cOnly = true
	defer rt.Retire()

	req := httptest.NewRequest(http.MethodGet, backend.URL+"/", nil)
	req.RequestURI = ""
	markFinalScheme(req)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("an http:// target on an h2c-only API was sent over h2c: %v", err)
	}
	resp.Body.Close()
	if proto != "HTTP/1.1" {
		t.Fatalf("backend saw %q, want HTTP/1.1", proto)
	}
}

func TestTykRoundTripper_RetireIsSafeDuringRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rt := &TykRoundTripper{transport: &http.Transport{}}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req, _ := http.NewRequest(http.MethodGet, backend.URL, nil)
				if resp, err := rt.RoundTrip(req); err == nil {
					resp.Body.Close()
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		rt.Retire()
	}
	wg.Wait()
}

func TestDNSDiscovery_ProtocolChangeReleasesTheRegistry(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.upstreamDNS.Lookup = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	ts.Gw.upstreamDNS.Jitter = func(d time.Duration) time.Duration { return d }

	const apiID = "dns-protocol-change"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/dns-protocol-change/"
		spec.UseKeylessAccess = true
		spec.Proxy.TargetURL = "h2c://svc.example:9002"
		spec.Proxy.EnableLoadBalancing = true
		spec.Proxy.DNSDiscovery.Enabled = true
		drainingIn(80 * time.Millisecond)(spec)
	})

	live := ts.Gw.getApiSpec(apiID)
	if live == nil || live.dnsDiscovery.Load() == nil {
		t.Fatal("the HTTP API was not loaded with DNS discovery")
	}
	registry := live.dnsDiscovery.Load().conns
	tracked := trackConn(t, registry, "127.0.0.1:9002", planSelection(live))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ts.EnablePort(port, "tcp")

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "tcp"
		spec.ListenPort = port
		spec.Proxy.TargetURL = "127.0.0.1:9"
	})

	if !closedWithin(t, tracked, time.Second) {
		t.Fatal("replacing the discovered HTTP API with a TCP API left its connection without a drain deadline")
	}
	if got := ts.Gw.upstreamConns.get(apiID, nil); got == registry {
		t.Fatal("the replaced API's registry is still held by the gateway")
	}
}
