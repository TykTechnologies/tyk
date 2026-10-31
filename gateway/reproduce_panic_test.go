package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func TestMaxLatencyWriterPanic(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("not a hijacker")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Write a response directly to the connection
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n")
		bufrw.Flush()

		// Now simulate maxLatencyWriter's delayedFlush
		// We need to pass the ResponseWriter to maxLatencyWriter
		// But maxLatencyWriter expects a writeFlusher
		wf, ok := w.(writeFlusher)
		if !ok {
			t.Fatal("not a writeFlusher")
		}

		mlw := &maxLatencyWriter{
			dst:          wf,
			latency:      -1,
			flushPending: true, // Set to true so delayedFlush actually calls Flush
		}

		// This should panic
		mlw.delayedFlush()
	})

	// Wrap with otelhttp
	otelHandler := otelhttp.NewHandler(handler, "test")

	srv := httptest.NewServer(otelHandler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
}
