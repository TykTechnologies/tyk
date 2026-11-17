package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type openConns struct {
	count atomic.Int64
}

func (o *openConns) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	o.count.Add(1)
	return &trackedUpstreamConn{Conn: conn, open: o}, nil
}

func (o *openConns) closeWithin(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for o.count.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d upstream connections still open after the round tripper was retired", o.count.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type trackedUpstreamConn struct {
	net.Conn
	open   *openConns
	closed atomic.Bool
}

func (c *trackedUpstreamConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.open.count.Add(-1)
	}
	return c.Conn.Close()
}

func TestTykRoundTripper_RetiredTransportDoesNotPoolLateRequests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	})

	t.Run("http1", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		open := &openConns{}
		rt := &TykRoundTripper{transport: &http.Transport{DialContext: open.dial}}
		assertLateRequestNotPooled(t, rt, open, server.URL, 1)
	})

	t.Run("http2 over TLS", func(t *testing.T) {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.StartTLS()
		defer server.Close()

		open := &openConns{}
		transport := server.Client().Transport.(*http.Transport).Clone()
		transport.DialContext = open.dial
		rt := &TykRoundTripper{transport: transport}
		assertLateRequestNotPooled(t, rt, open, server.URL, 2)
	})
}

func assertLateRequestNotPooled(t *testing.T, rt *TykRoundTripper, open *openConns, url string, proto int) {
	t.Helper()

	rt.Retire()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("request through the retired transport failed: %v", err)
	}
	if res.ProtoMajor != proto {
		t.Fatalf("response over HTTP/%d, want HTTP/%d", res.ProtoMajor, proto)
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}

	open.closeWithin(t, time.Second)
}
