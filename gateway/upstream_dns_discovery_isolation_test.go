package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestProcessSpecWithoutUpstreamDNSDiscovery(t *testing.T) {
	resolver := newStubResolver()
	resolver.set("svc", "10.0.0.1", "10.0.0.2")

	gw := newDiscoveryGateway(t, resolver)
	live := loadDiscoveredAPI(t, gw, "api-1", "h2c://svc:9002")

	before, _ := gw.urlFromDNS(live)

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.SetLevel(logrus.PanicLevel)

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

	lookupsBefore := gw.upstreamDNS.Lookups()
	resolver.set("svc", "10.0.0.3")
	gw.upstreamDNS.Refresh(context.Background())

	if gw.upstreamDNS.Lookups() == lookupsBefore {
		t.Fatal("the live API's hostname is no longer being resolved")
	}

	after, _ := gw.urlFromDNS(live)
	if len(after.All()) != 1 || after.All()[0] != "h2c://10.0.0.3:9002" {
		t.Fatalf("live API did not follow the address change: before %v, after %v", before.All(), after.All())
	}
}

func TestRetireLetsInFlightH2CRequestsFinish(t *testing.T) {
	for _, discovered := range []bool{true, false} {
		name := "discovered"
		if !discovered {
			name = "unowned"
		}
		t.Run(name, func(t *testing.T) {
			finishStream := make(chan struct{})
			backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stream" {
					_, _ = io.WriteString(w, "before retirement\n")
					w.(http.Flusher).Flush()
					select {
					case <-finishStream:
					case <-r.Context().Done():
						return
					}
				}
				_, _ = io.WriteString(w, "after retirement\n")
			}), &http2.Server{}))
			defer backend.Close()

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			rt := newH2CRoundTripper(spec, &http.Transport{})
			defer rt.Retire()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			do := func(path string) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				markUpstream(req, upstreamMark{h2c: true, discovered: discovered})
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatalf("request to %s failed: %v", path, err)
				}
				t.Cleanup(func() { resp.Body.Close() })
				if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
					t.Fatalf("unexpected response: %s %s", resp.Proto, resp.Status)
				}
				return resp
			}

			resp := do("/stream")
			prefix := make([]byte, len("before retirement\n"))
			if _, err := io.ReadFull(resp.Body, prefix); err != nil {
				t.Fatalf("reading the stream before retirement: %v", err)
			}
			if string(prefix) != "before retirement\n" {
				t.Fatalf("unexpected stream prefix: %q", prefix)
			}

			// The backend cannot finish the response until after retirement.
			rt.Retire()
			close(finishStream)
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "after retirement\n" {
				t.Fatalf("retirement interrupted the active stream: body %q, error %v", body, err)
			}

			// Close the now-idle connection so the next request must dial again.
			// Requests already holding a replaced transport must still be served.
			rt.Retire()
			resp = do("/after")
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "after retirement\n" {
				t.Fatalf("request through the retired transport failed: body %q, error %v", body, err)
			}
		})
	}
}
