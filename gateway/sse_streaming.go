package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// prepareSSEStreaming configures the write deadline for SSE streams.
//
// Default behaviour: regular APIs keep the server's write_timeout.
// When SSEWriteTimeoutDisabled is true (or for MCP Proxies as backwards compat),
// the deadline is cleared so streams live indefinitely.
// When SSEWriteTimeout > 0 is set on any API, an idle-timeout writer is
// returned that resets the deadline after each write and terminates the stream
// if no data flows within the window.
//
// Returns (nil, nil) when no writer wrapper is needed.
func (p *ReverseProxy) prepareSSEStreaming(rw http.ResponseWriter, body io.Closer) (io.Writer, func()) {
	rc := http.NewResponseController(rw)
	idleTimeout := p.TykAPISpec.Proxy.SSEWriteTimeout

	if idleTimeout > 0 {
		// Explicit idle timeout: close the stream if no data is written
		// within the window.
		timeout := time.Duration(idleTimeout) * time.Second
		if err := rc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			p.logger.WithError(err).Debug("failed to set SSE idle write deadline")
			return nil, nil
		}
		wf, ok := rw.(writeFlusher)
		if !ok {
			return nil, nil
		}
		// If body is an SSETap, close the underlying reader directly so
		// the timer callback does not contend with SSETap's mutex.
		timeoutCloser := body
		if tap, ok := body.(*SSETap); ok {
			timeoutCloser = tap.UnderlyingCloser()
		}
		dw := newDeadlineWriter(wf, rc, timeout, timeoutCloser)
		return dw, dw.stop
	}

	// Clear deadline if explicitly disabled, or for MCP Proxies (backwards compat).
	if p.TykAPISpec.Proxy.SSEWriteTimeoutDisabled || p.TykAPISpec.IsMCP() {
		if err := rc.SetWriteDeadline(time.Time{}); err != nil {
			p.logger.WithError(err).Debug("failed to clear write deadline for SSE stream")
		}
	}

	return nil, nil
}

// handleCopyError sends an SSE error event to the client when the upstream
// body copy fails unexpectedly. Client-initiated disconnects (context.Canceled)
// are silently ignored.
//
// After writing and flushing the error event, the function hijacks the
// underlying TCP connection and closes it. This prevents Go's net/http server
// from returning the connection to the keep-alive pool. Without this, the
// pooled connection retains a cleared write deadline (from
// prepareSSEStreaming), and any subsequent request reusing that connection
// would have no write deadline, risking goroutine leaks if the client stalls.
func (p *ReverseProxy) handleCopyError(rw http.ResponseWriter, copyErr error, isStreaming bool) {
	if !isStreaming {
		return
	}
	// Ignore client disconnects, context timeouts, and deliberate idle-timeout
	// body closes — these are normal lifecycle events, not upstream failures.
	if errors.Is(copyErr, context.Canceled) || errors.Is(copyErr, context.DeadlineExceeded) || errors.Is(copyErr, net.ErrClosed) {
		return
	}
	const errorEvent = "event: error\ndata: upstream connection terminated unexpectedly\n\n"
	_, _ = io.WriteString(rw, errorEvent)
	if flusher, ok := rw.(http.Flusher); ok {
		flusher.Flush()
	}

	// Hijack the connection and close it so it cannot be reused via keep-alive,
	// but only when prepareSSEStreaming cleared the write deadline. Without the
	// hijack, Go's net/http server would return the connection to the keep-alive
	// pool with no write deadline, risking goroutine leaks if the client stalls.
	//
	// When the deadline was NOT cleared (regular SSE proxying), we must not
	// hijack because that would prevent the HTTP server from sending the
	// chunked transfer-encoding termination, causing the client to see an
	// unexpected EOF.
	deadlineCleared := p.TykAPISpec.Proxy.SSEWriteTimeout == 0 &&
		(p.TykAPISpec.Proxy.SSEWriteTimeoutDisabled || p.TykAPISpec.IsMCP())
	if deadlineCleared {
		if hj, ok := rw.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	}
}

// deadlineWriter wraps a writeFlusher and implements an idle timeout for SSE
// streams. After each successful write the idle timer resets. If no write
// occurs within the timeout window, the upstream response body is closed to
// unblock the copy loop and terminate the stream.
type deadlineWriter struct {
	dst     writeFlusher
	rc      *http.ResponseController
	timeout time.Duration
	timer   *time.Timer
}

func newDeadlineWriter(dst writeFlusher, rc *http.ResponseController, timeout time.Duration, body io.Closer) *deadlineWriter {
	dw := &deadlineWriter{
		dst:     dst,
		rc:      rc,
		timeout: timeout,
	}
	dw.timer = time.AfterFunc(timeout, func() {
		// Close the upstream body to unblock the read side of copyBuffer.
		body.Close()
	})
	return dw
}

func (dw *deadlineWriter) Write(p []byte) (n int, err error) {
	n, err = dw.dst.Write(p)
	if n > 0 {
		dw.timer.Reset(dw.timeout)
		_ = dw.rc.SetWriteDeadline(time.Now().Add(dw.timeout))
	}
	return
}

func (dw *deadlineWriter) Flush() {
	dw.dst.Flush()
}

func (dw *deadlineWriter) stop() {
	dw.timer.Stop()
}
