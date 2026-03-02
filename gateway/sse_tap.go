package gateway

import (
	"bytes"
	"io"
	"sync"
)

// readChunkSize is the number of bytes read from the upstream body in a single
// call. 4 KB is a reasonable default for SSE where events are typically small.
const readChunkSize = 4096

// maxInputBufferSize is the maximum number of bytes the input buffer is allowed
// to accumulate before being flushed as-is. This prevents a malicious or buggy
// upstream from consuming unbounded memory by never sending an event boundary.
const maxInputBufferSize = 1 << 20 // 1 MB

// SSETap wraps an upstream http.Response.Body and intercepts individual SSE
// events, running them through a chain of SSEHook implementations before
// forwarding them to the downstream consumer (typically CopyResponse).
//
// When no hooks are registered the tap operates in pass-through mode with
// minimal overhead: raw bytes are forwarded without parsing.
//
// SSETap implements io.ReadCloser and is safe for concurrent use.
// The mutex is released during blocking upstream reads so that Close can
// be called from another goroutine (e.g. a deadline timer) without deadlocking.
type SSETap struct {
	reader       io.ReadCloser // upstream response body
	inputBuffer  []byte        // accumulates raw upstream bytes
	outputBuffer bytes.Buffer  // holds serialized events ready for the client
	upstreamEOF  bool          // set once the upstream reader returns io.EOF
	closed       bool          // set by Close; checked after re-acquiring the mutex
	hooks        []SSEHook
	mu           sync.Mutex
	readBuf      [readChunkSize]byte // reusable read buffer — avoids per-Read allocation
}

// NewSSETap creates a new SSETap wrapping reader. If no hooks are provided
// the tap operates in a fast pass-through mode.
func NewSSETap(reader io.ReadCloser, hooks ...SSEHook) *SSETap {
	return &SSETap{
		reader: reader,
		hooks:  hooks,
	}
}

// Read satisfies io.Reader. It never returns (0, nil) which would violate the
// io.Reader contract. It loops internally until output data is available, the
// upstream reaches EOF, or an error occurs.
//
// The mutex is released while waiting on the upstream reader so that Close
// can be called concurrently (e.g. from a deadline timer) without deadlocking.
func (t *SSETap) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	noProgressCount := 0

	for {
		// 1. Drain any buffered output first.
		if t.outputBuffer.Len() > 0 {
			return t.outputBuffer.Read(p)
		}

		// 2. If upstream is done and no output remains, signal EOF.
		if t.upstreamEOF {
			return 0, io.EOF
		}

		// 3. If we were closed, return immediately.
		if t.closed {
			return 0, io.ErrClosedPipe
		}

		// 4. Read a chunk from the upstream body. Release the mutex so
		// that Close can proceed if a deadline timer fires while the
		// upstream read blocks.
		t.mu.Unlock()
		n, err := t.reader.Read(t.readBuf[:])
		t.mu.Lock()

		// Re-check closed: Close may have been called while we were
		// waiting on the upstream reader.
		if t.closed {
			return 0, io.ErrClosedPipe
		}

		if n > 0 {
			t.inputBuffer = append(t.inputBuffer, t.readBuf[:n]...)
			noProgressCount = 0
		}

		if err == io.EOF {
			t.upstreamEOF = true
		} else if err != nil {
			return 0, err
		}

		// Guard against upstream readers that return (0, nil), which violates
		// the io.Reader contract but can happen in practice. Bail out after a
		// few consecutive no-progress reads to avoid spinning.
		if n == 0 && err == nil {
			noProgressCount++
			if noProgressCount >= 3 {
				return 0, io.ErrNoProgress
			}
			continue
		}

		// 5. Process any complete events in the input buffer.
		t.processInputBuffer()

		// 6. If the input buffer has grown past the safety limit without
		// producing a complete event boundary, flush it as-is (fail-open)
		// to prevent unbounded memory growth from a malicious upstream.
		if len(t.inputBuffer) > maxInputBufferSize {
			t.outputBuffer.Write(t.inputBuffer)
			t.inputBuffer = nil
		}

		// 7. If we produced output, the next iteration will return it.
		// If upstream hit EOF but processInputBuffer produced nothing,
		// flush any remaining unparseable bytes as-is (fail-open).
		if t.outputBuffer.Len() == 0 && t.upstreamEOF {
			if len(t.inputBuffer) > 0 {
				// Forward leftover bytes unchanged (incomplete event
				// at stream end).
				t.outputBuffer.Write(t.inputBuffer)
				t.inputBuffer = nil
			}
		}

		// Loop continues; next iteration will either return output or EOF.
	}
}

// Close releases all internal buffers and closes the underlying reader.
// It is safe to call from a different goroutine while Read is blocked;
// the closed flag unblocks Read after the underlying reader is closed.
func (t *SSETap) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	t.inputBuffer = nil
	t.outputBuffer.Reset()

	return t.reader.Close()
}

// UnderlyingCloser returns the upstream reader's io.Closer. This allows
// callers (such as deadline timers) to close the underlying connection
// directly without going through SSETap's mutex.
func (t *SSETap) UnderlyingCloser() io.Closer {
	return t.reader
}

// processInputBuffer parses complete SSE events from inputBuffer, runs them
// through all registered hooks, and writes allowed (possibly modified) events
// to outputBuffer.
//
// When no hooks are registered, raw event bytes are forwarded directly to
// avoid the cost of serialization.
func (t *SSETap) processInputBuffer() {
	passthrough := len(t.hooks) == 0

	for {
		event, rawBytes, rest, err := parseSSEEvent(t.inputBuffer)
		if err != nil {
			// errIncompleteEvent: wait for more data.
			return
		}

		// Copy rest into a new slice so the old backing array can be GC'd.
		t.inputBuffer = append([]byte(nil), rest...)

		if passthrough {
			// No hooks: forward raw bytes unchanged.
			t.outputBuffer.Write(rawBytes)
			continue
		}

		if event == nil {
			// Block was only comments/empty; forward raw bytes to preserve
			// comments in the stream.
			t.outputBuffer.Write(rawBytes)
			continue
		}

		// Run through hooks.
		allowed := true
		current := event
		for _, hook := range t.hooks {
			hookAllowed, modified := hook.FilterEvent(current)
			if !hookAllowed {
				allowed = false
				break
			}
			if modified != nil {
				current = modified
			}
		}

		if !allowed {
			continue // drop the event
		}

		// If any hook modified the event, serialize the modified version.
		if current != event {
			t.outputBuffer.Write(serializeSSEEvent(current))
		} else {
			// No modification; forward original bytes to preserve formatting.
			t.outputBuffer.Write(rawBytes)
		}
	}
}
