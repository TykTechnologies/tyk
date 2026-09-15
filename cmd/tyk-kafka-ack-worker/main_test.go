package main

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type responseRecorder struct {
	header http.Header
	status int
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}
func (*responseRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *responseRecorder) WriteHeader(status int)    { r.status = status }

func TestWorkerRetriesAckAndJournalIsIdempotent(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		status := http.StatusAccepted
		if calls.Add(1) == 1 {
			status = http.StatusServiceUnavailable
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	j, err := openJournal(filepath.Join(t.TempDir(), "journal"))
	require.NoError(t, err)
	w := &worker{ackURL: "http://ack.invalid", client: client, journal: j, attempts: 3}
	request := func() *http.Request {
		r, requestErr := http.NewRequest(http.MethodPost, "http://worker.invalid/process", strings.NewReader("{}"))
		require.NoError(t, requestErr)
		r.Header.Set("Tyk-Kafka-Message-ID", "event-1")
		r.Header.Set("Tyk-Kafka-Ack-Token", "token")
		return r
	}
	rw := &responseRecorder{}
	w.process(rw, request())
	require.Equal(t, http.StatusNoContent, rw.status)
	require.EqualValues(t, 2, calls.Load())
	applied, err := j.apply("event-1", nil)
	require.NoError(t, err)
	require.False(t, applied)
	rw = &responseRecorder{}
	w.process(rw, request())
	require.Equal(t, http.StatusNoContent, rw.status)
}
