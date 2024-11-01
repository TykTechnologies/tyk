//go:build ee || dev

package gateway

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/ee/middleware/streams"
)

type DefaultStreamAnalyticsFactory struct {
	Logger *logrus.Entry
	Gw     *Gateway
	Spec   *APISpec
}

func NewStreamAnalyticsFactory(logger *logrus.Entry, gw *Gateway, spec *APISpec) streams.StreamAnalyticsFactory {
	return &DefaultStreamAnalyticsFactory{
		Logger: logger,
		Gw:     gw,
		Spec:   spec,
	}
}

func (d *DefaultStreamAnalyticsFactory) CreateRecorder(r *http.Request) streams.StreamAnalyticsRecorder {
	detailed := false
	if recordDetailUnsafe(r, d.Spec) {
		detailed = true
	}

	if isWebsocketUpgrade(r) {
		return NewWebSocketStreamAnalyticsRecorder(d.Gw, d.Spec, detailed)
	}

	return NewDefaultStreamAnalyticsRecorder(d.Gw, d.Spec)
}

func (d *DefaultStreamAnalyticsFactory) CreateResponseWriter(w http.ResponseWriter, r *http.Request, streamID string, recorder streams.StreamAnalyticsRecorder) http.ResponseWriter {
	return NewStreamAnalyticsResponseWriter(d.Logger, w, r, streamID, recorder)
}

type DefaultStreamAnalyticsRecorder struct {
	Gw       *Gateway
	Spec     *APISpec
	reqCopy  *http.Request
	respCopy *http.Response
}

func NewDefaultStreamAnalyticsRecorder(gw *Gateway, spec *APISpec) *DefaultStreamAnalyticsRecorder {
	return &DefaultStreamAnalyticsRecorder{
		Gw:   gw,
		Spec: spec,
	}
}

func (s *DefaultStreamAnalyticsRecorder) PrepareRecord(r *http.Request) {
	s.reqCopy = r.Clone(r.Context())
	s.respCopy = &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	s.respCopy.Header.Set("Content-Length", strconv.FormatInt(0, 10))
	s.respCopy.Body = io.NopCloser(strings.NewReader(""))
	s.respCopy.ContentLength = 0
}

func (s *DefaultStreamAnalyticsRecorder) RecordHit(statusCode int, latency analytics.Latency) error {
	s.respCopy.StatusCode = statusCode

	handler := SuccessHandler{
		&BaseMiddleware{
			Spec: s.Spec,
			Gw:   s.Gw,
		},
	}

	handler.RecordHit(s.reqCopy, latency, statusCode, s.respCopy, false)
	return nil
}

type WebSocketStreamAnalyticsRecorder struct {
	Gw                            *Gateway
	Spec                          *APISpec
	Detailed                      bool
	simpleStreamAnalyticsRecorder *DefaultStreamAnalyticsRecorder
}

func NewWebSocketStreamAnalyticsRecorder(gw *Gateway, spec *APISpec, detailed bool) *WebSocketStreamAnalyticsRecorder {
	return &WebSocketStreamAnalyticsRecorder{
		Gw:                            gw,
		Spec:                          spec,
		Detailed:                      detailed,
		simpleStreamAnalyticsRecorder: NewDefaultStreamAnalyticsRecorder(gw, spec),
	}
}

func (d *WebSocketStreamAnalyticsRecorder) PrepareRecord(r *http.Request) {
	d.simpleStreamAnalyticsRecorder.PrepareRecord(r)
}

func (d *WebSocketStreamAnalyticsRecorder) RecordHit(statusCode int, latency analytics.Latency) error {
	return d.simpleStreamAnalyticsRecorder.RecordHit(statusCode, latency)
}

type StreamAnalyticsResponseWriter struct {
	logger            *logrus.Entry
	w                 http.ResponseWriter
	r                 *http.Request
	streamID          string
	recorder          streams.StreamAnalyticsRecorder
	writtenStatusCode int
}

func NewStreamAnalyticsResponseWriter(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, streamID string, recorder streams.StreamAnalyticsRecorder) *StreamAnalyticsResponseWriter {
	return &StreamAnalyticsResponseWriter{
		logger:            logger,
		w:                 w,
		r:                 r,
		streamID:          streamID,
		recorder:          recorder,
		writtenStatusCode: http.StatusOK, // implicit status code from ResponseWriter.Write
	}
}

func (s *StreamAnalyticsResponseWriter) SetStreamID(streamID string) {
	s.streamID = streamID
}

func (s *StreamAnalyticsResponseWriter) Header() http.Header {
	return s.w.Header()
}

func (s *StreamAnalyticsResponseWriter) Write(bytes []byte) (int, error) {
	now := time.Now()
	n, err := s.w.Write(bytes)
	if err != nil {
		return n, err
	}

	totalMillisecond := DurationToMillisecond(time.Since(now))
	latency := analytics.Latency{
		Total:    int64(totalMillisecond),
		Upstream: int64(totalMillisecond),
	}

	s.recorder.PrepareRecord(s.r)
	recorderErr := s.recorder.RecordHit(s.writtenStatusCode, latency)
	if recorderErr != nil {
		s.logger.Errorf("Failed to record analytics for stream on path '%s %s', %v", s.r.Method, s.r.URL.Path, recorderErr)
	}
	return n, nil
}

func (s *StreamAnalyticsResponseWriter) WriteHeader(statusCode int) {
	s.writtenStatusCode = statusCode
	s.w.WriteHeader(statusCode)
}

func (s *StreamAnalyticsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijackableWriter, ok := s.w.(http.Hijacker)
	if !ok {
		return nil, nil, streams.ErrResponseWriterNotHijackable
	}

	s.recorder.PrepareRecord(s.r)
	recorderErr := s.recorder.RecordHit(http.StatusSwitchingProtocols, analytics.Latency{})
	if recorderErr != nil {
		s.logger.Errorf("Failed to record analytics for connection upgrade on path 'UPGRADE %s', %v", s.r.URL.Path, recorderErr)
	}

	return hijackableWriter.Hijack()
}

func (s *StreamAnalyticsResponseWriter) Flush() {
	if flusher, ok := s.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func isWebsocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
