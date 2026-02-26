package gateway

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

// trackingCloser wraps a reader and records whether Close was called.
type trackingCloser struct {
	io.Reader
	closed bool
	mu     sync.Mutex
}

func (tc *trackingCloser) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.closed = true
	return nil
}

func (tc *trackingCloser) wasClosed() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.closed
}

// chunkedReader delivers data in fixed-size chunks to simulate TCP reads.
type chunkedReader struct {
	data      []byte
	chunkSize int
	pos       int
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.pos >= len(cr.data) {
		return 0, io.EOF
	}
	end := cr.pos + cr.chunkSize
	if end > len(cr.data) {
		end = len(cr.data)
	}
	n := copy(p, cr.data[cr.pos:end])
	cr.pos += n
	return n, nil
}

func (cr *chunkedReader) Close() error { return nil }

// readAll reads all bytes from r into a string.
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(data)
}

// buildEvents creates n SSE events in wire format.
func buildEvents(n int) string {
	var buf strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&buf, "data: event-%d\n\n", i)
	}
	return buf.String()
}

// --- hook implementations for tests ---

// passHook allows all events unchanged.
type passHook struct{}

func (h *passHook) FilterEvent(_ *SSEEvent) (bool, *SSEEvent) {
	return true, nil
}

// dropHook drops events whose data contains the target string.
type dropHook struct {
	target string
}

func (h *dropHook) FilterEvent(event *SSEEvent) (bool, *SSEEvent) {
	for _, d := range event.Data {
		if strings.Contains(d, h.target) {
			return false, nil
		}
	}
	return true, nil
}

// modifyHook replaces data content matching old with new.
type modifyHook struct {
	old string
	new string
}

func (h *modifyHook) FilterEvent(event *SSEEvent) (bool, *SSEEvent) {
	modified := false
	newData := make([]string, len(event.Data))
	for i, d := range event.Data {
		if strings.Contains(d, h.old) {
			newData[i] = strings.ReplaceAll(d, h.old, h.new)
			modified = true
		} else {
			newData[i] = d
		}
	}
	if !modified {
		return true, nil
	}
	return true, &SSEEvent{
		ID:    event.ID,
		Event: event.Event,
		Data:  newData,
		Retry: event.Retry,
	}
}

// --- tests ---

func TestSSETap_PassThrough_NoHooks(t *testing.T) {
	t.Parallel()

	input := buildEvents(5)
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Equal(t, input, got, "all events should pass through byte-for-byte")
}

func TestSSETap_PassThrough_WithPassHook(t *testing.T) {
	t.Parallel()

	input := buildEvents(5)
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body, &passHook{})

	got := readAll(t, tap)
	assert.Equal(t, input, got, "pass hook should forward all events unchanged")
}

func TestSSETap_HookFiltersEvent(t *testing.T) {
	t.Parallel()

	input := "data: allowed-1\n\ndata: blocked\n\ndata: allowed-2\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body, &dropHook{target: "blocked"})

	got := readAll(t, tap)
	want := "data: allowed-1\n\ndata: allowed-2\n\n"
	assert.Equal(t, want, got, "blocked event should be dropped")
}

func TestSSETap_HookModifiesEvent(t *testing.T) {
	t.Parallel()

	input := "data: hello world\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body, &modifyHook{old: "hello", new: "goodbye"})

	got := readAll(t, tap)
	want := "data: goodbye world\n\n"
	assert.Equal(t, want, got, "modified event should appear in output")
}

func TestSSETap_PartialEventBuffering(t *testing.T) {
	t.Parallel()

	// Event split across two small reads.
	input := "data: split-across-chunks\n\n"
	body := &chunkedReader{data: []byte(input), chunkSize: 5}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Equal(t, input, got, "partial events should be reassembled")
}

func TestSSETap_UpstreamEOF_FlushesRemaining(t *testing.T) {
	t.Parallel()

	// Incomplete event at EOF should be forwarded as-is (fail-open).
	input := "data: incomplete"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Equal(t, input, got, "incomplete data at EOF should be forwarded")
}

func TestSSETap_Close_CleansUp(t *testing.T) {
	t.Parallel()

	body := &trackingCloser{Reader: strings.NewReader("data: x\n\n")}
	tap := NewSSETap(body)

	err := tap.Close()
	require.NoError(t, err)
	assert.True(t, body.wasClosed(), "underlying reader should be closed")
}

func TestSSETap_Close_SubsequentReadReturnsError(t *testing.T) {
	t.Parallel()

	body := &trackingCloser{Reader: strings.NewReader("data: x\n\n")}
	tap := NewSSETap(body)
	require.NoError(t, tap.Close())

	// After Close, reading should not panic. The underlying reader is closed
	// so behaviour depends on the reader, but we should not get (0, nil).
	buf := make([]byte, 128)
	n, err := tap.Read(buf)
	// After close, either EOF or an error is acceptable; (0, nil) is not.
	if n == 0 {
		assert.Error(t, err, "Read after Close should return an error or EOF")
	}
}

func TestSSETap_ReadNeverReturnsZeroNil(t *testing.T) {
	t.Parallel()

	// Use chunked reader to create multiple short reads.
	input := buildEvents(3)
	body := &chunkedReader{data: []byte(input), chunkSize: 7}
	tap := NewSSETap(body)

	buf := make([]byte, 2) // tiny buffer to force many Read calls
	var total int
	for {
		n, err := tap.Read(buf)
		if n == 0 && err == nil {
			t.Fatal("Read returned (0, nil) violating io.Reader contract")
		}
		total += n
		if err != nil {
			assert.ErrorIs(t, err, io.EOF)
			break
		}
	}
	assert.Equal(t, len(input), total)
}

func TestSSETap_CommentEvents_ForwardedInPassthrough(t *testing.T) {
	t.Parallel()

	input := ": keep-alive\n\ndata: real\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Equal(t, input, got, "comment-only blocks should pass through")
}

func TestSSETap_CommentEvents_ForwardedWithHooks(t *testing.T) {
	t.Parallel()

	input := ": keep-alive\n\ndata: real\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body, &passHook{})

	got := readAll(t, tap)
	assert.Equal(t, input, got, "comment-only blocks should pass through with hooks")
}

func TestSSETap_MultipleHooks_ChainedCorrectly(t *testing.T) {
	t.Parallel()

	// First hook modifies, second hook drops if data contains "DROP".
	input := "data: hello\n\ndata: DROP\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body,
		&modifyHook{old: "hello", new: "modified"},
		&dropHook{target: "DROP"},
	)

	got := readAll(t, tap)
	want := "data: modified\n\n"
	assert.Equal(t, want, got)
}

func TestSSETap_MemoryBounded(t *testing.T) {
	t.Parallel()

	// Send 10,000 events of ~1 KB each through the tap and verify memory
	// does not grow proportionally to total stream size.
	const eventCount = 10000
	payload := strings.Repeat("x", 1000)
	var eventBuf bytes.Buffer
	for i := 0; i < eventCount; i++ {
		fmt.Fprintf(&eventBuf, "data: %s-%d\n\n", payload, i)
	}

	body := &trackingCloser{Reader: bytes.NewReader(eventBuf.Bytes())}
	tap := NewSSETap(body, &passHook{})

	// Read all output, discarding it.
	buf := make([]byte, 8192)
	totalRead := 0
	for {
		n, err := tap.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
	}

	assert.Equal(t, eventBuf.Len(), totalRead)

	// Force GC and check that the tap's internal buffers are small.
	runtime.GC()

	tap.mu.Lock()
	inputLen := len(tap.inputBuffer)
	outputLen := tap.outputBuffer.Len()
	tap.mu.Unlock()

	// After reading everything, buffers should be empty or near-empty.
	assert.Less(t, inputLen, 4096, "input buffer should not grow unbounded")
	assert.Less(t, outputLen, 4096, "output buffer should not grow unbounded")
}

func TestSSETap_EventWithAllLineEndings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"LF", "data: hello\n\n"},
		{"CRLF", "data: hello\r\n\r\n"},
		{"CR", "data: hello\r\r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := &trackingCloser{Reader: strings.NewReader(tt.input)}
			tap := NewSSETap(body)
			got := readAll(t, tap)
			assert.Equal(t, tt.input, got)
		})
	}
}

func TestSSETap_LargeEvent(t *testing.T) {
	t.Parallel()

	// A single event with a large data payload (100 KB).
	bigPayload := strings.Repeat("A", 100*1024)
	input := "data: " + bigPayload + "\n\n"
	body := &trackingCloser{Reader: strings.NewReader(input)}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Equal(t, input, got)
}

func TestSSETap_EmptyStream(t *testing.T) {
	t.Parallel()

	body := &trackingCloser{Reader: strings.NewReader("")}
	tap := NewSSETap(body)

	got := readAll(t, tap)
	assert.Empty(t, got)
}

// --- benchmarks ---

func BenchmarkSSETap_NoHooks(b *testing.B) {
	input := []byte(buildEvents(100))
	b.SetBytes(int64(len(input)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		body := &chunkedReader{data: input, chunkSize: 4096}
		tap := NewSSETap(body)
		_, _ = io.Copy(io.Discard, tap)
	}
}

func BenchmarkSSETap_WithHook(b *testing.B) {
	input := []byte(buildEvents(100))
	b.SetBytes(int64(len(input)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		body := &chunkedReader{data: input, chunkSize: 4096}
		tap := NewSSETap(body, &passHook{})
		_, _ = io.Copy(io.Discard, tap)
	}
}

func BenchmarkSSETap_PerEvent(b *testing.B) {
	// Measure per-event overhead.
	singleEvent := []byte("data: benchmark-payload-data\n\n")
	b.SetBytes(int64(len(singleEvent)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		body := &chunkedReader{data: singleEvent, chunkSize: 4096}
		tap := NewSSETap(body, &passHook{})
		_, _ = io.Copy(io.Discard, tap)
	}
}
