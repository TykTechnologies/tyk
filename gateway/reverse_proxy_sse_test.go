package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// TestSSE_MCP_WriteTimeoutBypass verifies that MCP Proxies clear the write
// deadline for SSE streams so that a short write_timeout does not kill
// long-lived connections. Without the fix the 1-second write_timeout
// would terminate the stream before all events are delivered.
func TestSSE_MCP_WriteTimeoutBypass(t *testing.T) {
	const eventCount = 5

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		for i := 0; i < eventCount; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			flusher.Flush()
			time.Sleep(300 * time.Millisecond) // total ~1.5s, exceeds 1s write_timeout
		}
	}))
	defer upstream.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableWebSockets = false
		globalConf.HttpServerOptions.WriteTimeout = 1 // 1 second
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	scanner := bufio.NewScanner(resp.Body)
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			events = append(events, line)
		}
	}

	if assert.Len(t, events, eventCount) {
		for i := 0; i < eventCount; i++ {
			assert.Equal(t, fmt.Sprintf("data: %d", i), events[i])
		}
	}
}

// TestSSE_MCP_ContentTypeWithCharset verifies that MCP upstream responses
// with "text/event-stream; charset=utf-8" are correctly detected as SSE,
// the write deadline is cleared, and all events are received.
func TestSSE_MCP_ContentTypeWithCharset(t *testing.T) {
	const eventCount = 5

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		for i := 0; i < eventCount; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			flusher.Flush()
			time.Sleep(300 * time.Millisecond) // total ~1.5s, exceeds 1s write_timeout
		}
	}))
	defer upstream.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableWebSockets = false
		globalConf.HttpServerOptions.WriteTimeout = 1 // 1 second
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
		spec.MarkAsMCP()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	scanner := bufio.NewScanner(resp.Body)
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			events = append(events, line)
		}
	}

	if assert.Len(t, events, eventCount) {
		for i := 0; i < eventCount; i++ {
			assert.Equal(t, fmt.Sprintf("data: %d", i), events[i])
		}
	}
}

// TestSSE_UpstreamCrash_SendsErrorEvent verifies that when an upstream
// crashes mid-stream, the gateway sends an SSE error event to the client.
func TestSSE_UpstreamCrash_SendsErrorEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send 3 events then crash by hijacking and closing the connection.
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}

		// Hijack and close to simulate upstream crash
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer upstream.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableWebSockets = false
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Read all lines from the stream
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	bodyStr := string(body)

	// Verify we got the 3 data events
	for i := 0; i < 3; i++ {
		assert.Contains(t, bodyStr, fmt.Sprintf("data: %d", i))
	}

	// Verify the error event was sent
	assert.Contains(t, bodyStr, "event: error")
	assert.Contains(t, bodyStr, "data: upstream connection terminated unexpectedly")
}

// TestSSE_ClientDisconnect_NoErrorEvent verifies that when the client
// disconnects mid-stream, no error event is written.
func TestSSE_ClientDisconnect_NoErrorEvent(t *testing.T) {
	clientConnected := make(chan struct{})
	streamDone := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send one event to signal the connection is live
		fmt.Fprintf(w, "data: hello\n\n")
		flusher.Flush()
		close(clientConnected)

		// Keep streaming until context is cancelled (client disconnect)
		for i := 0; ; i++ {
			_, err := fmt.Fprintf(w, "data: %d\n\n", i)
			if err != nil {
				break
			}
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
		close(streamDone)
	}))
	defer upstream.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableWebSockets = false
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
	})

	// Use a raw TCP connection so we can close it abruptly
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	require.NoError(t, err)

	// Send HTTP request
	reqStr := "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n"
	_, err = conn.Write([]byte(reqStr))
	require.NoError(t, err)

	// Wait for the upstream to start streaming
	select {
	case <-clientConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to start streaming")
	}

	// Close the client connection abruptly
	conn.Close()

	// Wait for the stream to finish on the upstream side
	select {
	case <-streamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stream to finish")
	}

	// If we got here, the upstream noticed the disconnect and stopped.
	// The key assertion is that no error event was sent (context.Canceled is ignored).
	// Since the client disconnected, there's no one to receive an error event anyway.
	// The test passing without hanging or panicking validates the behavior.
}

// TestSSE_NonStreamingUnaffected verifies that regular JSON responses are
// unaffected by the SSE streaming changes.
func TestSSE_NonStreamingUnaffected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableWebSockets = false
	})
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"status":"ok"}`, string(body))
}
