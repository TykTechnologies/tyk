package accesslog_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func TestRecord(t *testing.T) {
	latency := analytics.Latency{
		Total:    150,
		Upstream: 120,
		Gateway:  30,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?userid=1", nil)
	req.RemoteAddr = "0.0.0.0"
	req.Header.Set("User-Agent", "user-agent")

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := accesslog.NewRecord()
	record.WithRequest(req, latency)
	record.WithResponse(resp)

	got := record.Fields(nil)

	want := logrus.Fields{
		"prefix":           "access-log",
		"client_ip":        request.RealIP(req),
		"remote_addr":      "0.0.0.0",
		"host":             "example.com",
		"latency_gateway":  int64(30),
		"latency_total":    int64(150),
		"method":           http.MethodGet,
		"path":             "/path",
		"protocol":         "HTTP/1.1",
		"status":           http.StatusOK,
		"upstream_addr":    "http://example.com/path",
		"upstream_latency": int64(120),
		"user_agent":       "user-agent",
	}

	assert.Equal(t, want, got)
}

func TestWithTraceID(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  func() *http.Request
		expectTraceID bool
	}{
		{
			name: "no trace context - field not added",
			setupRequest: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			},
			expectTraceID: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.setupRequest()
			record := accesslog.NewRecord().WithTraceID(req)
			fields := record.Fields(nil)

			_, exists := fields["trace_id"]
			assert.Equal(t, tc.expectTraceID, exists)
		})
	}
}
