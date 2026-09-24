package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dnscache"
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
	rt := newH2CRoundTripper(spec, &http.Transport{}, (&net.Dialer{}).DialContext)
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
	if ts.Gw.upstreamConns.get(apiID, nil) == registry {
		t.Fatal("the replaced API's registry is still held by the gateway")
	}
}

func TestH2CTransport_DialsWithoutTheHTTP1Dialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gw := &Gateway{}
	gw.SetConfig(config.Config{}, true)
	gw.dnsCacheManager = dnscache.NewDnsCacheManager(gw.GetConfig().DnsCache.MultipleIPsHandleStrategy)
	var viaHTTP1Dialer atomic.Int64
	gw.dialCtxFn = func(context.Context, string, string) (net.Conn, error) {
		viaHTTP1Dialer.Add(1)
		return nil, errors.New("h2c dialled through the HTTP/1 dialer")
	}

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	proxy := &ReverseProxy{TykAPISpec: spec, Gw: gw, logger: logrus.NewEntry(logrus.New())}
	proxy.logger.Logger.SetLevel(logrus.PanicLevel)

	req := httptest.NewRequest(http.MethodPost, "http://svc:9002/greet", nil)
	outReq := req.Clone(req.Context())
	outReq.URL.Scheme = "h2c"
	rt := proxy.httpTransport(30, req, outReq)
	if rt.h2ctransport == nil {
		t.Fatal("no h2c transport was built for an h2c request")
	}
	defer rt.Retire()

	for name, pool := range map[string]*http2.Transport{"discovered": rt.h2ctransport, "rewritten": rt.h2cUnowned} {
		conn, err := pool.DialTLSContext(context.Background(), "tcp", ln.Addr().String(), nil)
		if err != nil {
			t.Fatalf("%s pool could not dial: %v", name, err)
		}
		conn.Close()
	}
	if viaHTTP1Dialer.Load() != 0 {
		t.Fatal("h2c dialled through the HTTP/1 dialer, which carries the DNS cache wrapper")
	}
}
