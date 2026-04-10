package streams

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

var (
	ErrResponseWriterNotHijackable = errors.New("ResponseWriter is not hijackable")
)

type StreamAnalyticsFactory interface {
	CreateRecorder(r *http.Request) StreamAnalyticsRecorder
	CreateResponseWriter(w http.ResponseWriter, r *http.Request, streamID string, recorder StreamAnalyticsRecorder) http.ResponseWriter
}

type NoopStreamAnalyticsFactory struct{}

func (n *NoopStreamAnalyticsFactory) CreateRecorder(r *http.Request) StreamAnalyticsRecorder {
	return &NoopStreamAnalyticsRecorder{}
}

func (n *NoopStreamAnalyticsFactory) CreateResponseWriter(w http.ResponseWriter, r *http.Request, streamID string, recorder StreamAnalyticsRecorder) http.ResponseWriter {
	return w
}

type StreamAnalyticsRecorder interface {
	PrepareRecord(r *http.Request)
	RecordHit(statusCode int, latency analytics.Latency) error
}

type NoopStreamAnalyticsRecorder struct{}

func (n *NoopStreamAnalyticsRecorder) PrepareRecord(r *http.Request) {
}

func (n *NoopStreamAnalyticsRecorder) RecordHit(statusCode int, latency analytics.Latency) error {
	return nil
}
