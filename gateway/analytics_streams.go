//go:build ee || dev

package gateway

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ee/middleware/streams"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/request"
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

	return NewDefaultStreamAnalyticsRecorder(d.Gw, d.Spec, detailed)
}

func (d *DefaultStreamAnalyticsFactory) CreateResponseWriter(w http.ResponseWriter, r *http.Request, streamID string, recorder streams.StreamAnalyticsRecorder) http.ResponseWriter {
	return NewStreamAnalyticsResponseWriter(d.Logger, w, r, streamID, recorder)
}

type DefaultStreamAnalyticsRecorder struct {
	Gw       *Gateway
	Spec     *APISpec
	Detailed bool
}

func NewDefaultStreamAnalyticsRecorder(gw *Gateway, spec *APISpec, detailed bool) *DefaultStreamAnalyticsRecorder {
	return &DefaultStreamAnalyticsRecorder{
		Gw:       gw,
		Spec:     spec,
		Detailed: detailed,
	}
}

func (s *DefaultStreamAnalyticsRecorder) CreateRecord(r *http.Request) *analytics.AnalyticsRecord {
	// Preparation for analytics record
	alias := ""
	oauthClientID := ""
	session := ctxGetSession(r)
	tags := make([]string, 0, estimateTagsCapacity(session, s.Spec))

	if session != nil {
		oauthClientID = session.OauthClientID
		alias = session.Alias
		tags = append(tags, getSessionTags(session)...)
	}

	if len(s.Spec.TagHeaders) > 0 {
		tags = tagHeaders(r, s.Spec.TagHeaders, tags)
	}

	if len(s.Spec.Tags) > 0 {
		tags = append(tags, s.Spec.Tags...)
	}

	trackEP := false
	trackedPath := r.URL.Path

	if p := ctxGetTrackedPath(r); p != "" {
		trackEP = true
		trackedPath = p
	}

	// Create record for started stream
	t := time.Now()
	return &analytics.AnalyticsRecord{
		Method:        r.Method,
		Host:          r.URL.Host,
		Path:          trackedPath,
		RawPath:       r.URL.Path,
		ContentLength: r.ContentLength,
		UserAgent:     r.Header.Get(header.UserAgent),
		Day:           t.Day(),
		Month:         t.Month(),
		Year:          t.Year(),
		Hour:          t.Hour(),
		ResponseCode:  http.StatusSwitchingProtocols,
		APIKey:        ctxGetAuthToken(r),
		TimeStamp:     t,
		APIVersion:    s.Spec.getVersionFromRequest(r),
		APIName:       s.Spec.Name,
		APIID:         s.Spec.APIID,
		OrgID:         s.Spec.OrgID,
		OauthID:       oauthClientID,
		RequestTime:   0,
		Latency:       analytics.Latency{},
		IPAddress:     request.RealIP(r),
		Geo:           analytics.GeoData{},
		Network:       analytics.NetworkStats{},
		Tags:          tags,
		Alias:         alias,
		TrackPath:     trackEP,
		ExpireAt:      t,
	}
}

func (s *DefaultStreamAnalyticsRecorder) RecordHit(record *analytics.AnalyticsRecord, statusCode int) error {
	return streamRecordHit(s.Gw, record, statusCode)
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
		simpleStreamAnalyticsRecorder: NewDefaultStreamAnalyticsRecorder(gw, spec, detailed),
	}
}

func (d *WebSocketStreamAnalyticsRecorder) CreateRecord(r *http.Request) *analytics.AnalyticsRecord {
	return d.simpleStreamAnalyticsRecorder.CreateRecord(r)
}

func (d *WebSocketStreamAnalyticsRecorder) RecordHit(record *analytics.AnalyticsRecord, statusCode int) error {
	return d.simpleStreamAnalyticsRecorder.RecordHit(record, statusCode)
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
	n, err := s.w.Write(bytes)
	if err != nil {
		return n, err
	}

	record := s.recorder.CreateRecord(s.r)
	recorderErr := s.recorder.RecordHit(record, s.writtenStatusCode)
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

	record := s.recorder.CreateRecord(s.r)
	recorderErr := s.recorder.RecordHit(record, http.StatusSwitchingProtocols)
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

func streamRecordHit(gw *Gateway, record *analytics.AnalyticsRecord, statusCode int) error {
	record.ResponseCode = statusCode
	return gw.Analytics.RecordHit(record)
}

func isWebsocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
