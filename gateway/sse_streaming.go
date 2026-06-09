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
// For MCP APIs the deadline is cleared so streams live indefinitely,
// mirroring how hijacked WebSocket connections bypass WriteTimeout.
func (p *ReverseProxy) prepareSSEStreaming(rw http.ResponseWriter, _ io.Closer) (io.Writer, func()) {
	if p.TykAPISpec.IsMCP() {
		rc := http.NewResponseController(rw)
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
	// but only when prepareSSEStreaming cleared the write deadline (MCP).
	// Without the hijack, Go's net/http server would return the connection to
	// the keep-alive pool with no write deadline, risking goroutine leaks if
	// the client stalls.
	//
	// When the deadline was NOT cleared (regular SSE proxying), we must not
	// hijack because that would prevent the HTTP server from sending the
	// chunked transfer-encoding termination, causing the client to see an
	// unexpected EOF.
	if p.TykAPISpec.IsMCP() {
		if hj, ok := rw.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
			}
		}
	}
}
