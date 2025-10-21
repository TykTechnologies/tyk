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
