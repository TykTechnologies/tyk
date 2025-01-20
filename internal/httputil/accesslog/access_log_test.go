package accesslog

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"github.com/TykTechnologies/tyk/request"

	"github.com/stretchr/testify/assert"
)

func TestNewRecord(t *testing.T) {
	record := NewRecord().Fields()

	assert.Equal(t, "access-log", record["prefix"])
	assert.NotNil(t, record["prefix"])
}

func TestNewRecordField(t *testing.T) {
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?userid=1", nil)
	req.RemoteAddr = "0.0.0.0"
	req.Header.Set("User-Agent", "user-agent")

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := NewRecord().WithClientIP(req).WithRemoteAddr(req).WithHost(req).WithLatencyTotal(latency).WithMethod(req).WithPath(req).WithProtocol(req).WithStatus(resp).WithUpstreamAddress(req).WithUpstreamLatency(latency).WithUserAgent(req).Fields()

	assert.Equal(t, "access-log", record["prefix"])
	assert.Equal(t, request.RealIP(req), record["client_ip"])
	assert.Equal(t, "0.0.0.0", record["remote_addr"])
	assert.Equal(t, "example.com", record["host"])
	assert.Equal(t, int64(99), record["latency_total"])
	assert.Equal(t, http.MethodGet, record["method"])
	assert.Equal(t, "/path", record["path"])
	assert.Equal(t, "HTTP/1.1", record["protocol"])
	assert.Equal(t, http.StatusOK, record["status"])
	assert.Equal(t, "http://example.com/path", record["upstream_address"])
	assert.Equal(t, int64(101), record["upstream_latency"])
	assert.Equal(t, "user-agent", record["user_agent"])
}
