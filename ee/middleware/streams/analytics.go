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
	CreateRecord(r *http.Request) *analytics.AnalyticsRecord
	RecordHit(record *analytics.AnalyticsRecord, statusCode int) error
}

type NoopStreamAnalyticsRecorder struct{}

func (n *NoopStreamAnalyticsRecorder) CreateRecord(r *http.Request) *analytics.AnalyticsRecord {
	return &analytics.AnalyticsRecord{}
}

func (n *NoopStreamAnalyticsRecorder) RecordHit(record *analytics.AnalyticsRecord, statusCode int) error {
	return nil
}
