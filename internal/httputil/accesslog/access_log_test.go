package accesslog

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/request"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

func TestNewRecord(t *testing.T) {
	record := NewRecord().Fields()

	assert.Equal(t, "access-log", record["prefix"])
	assert.NotNil(t, record["prefix"])
}

func TestNewRecordWithLatency(t *testing.T) {
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}

	record := NewRecord().WithLatency(latency).Fields()

	assert.Equal(t, latency.Total, record["total_latency"])
	assert.Equal(t, latency.Upstream, record["upstream_latency"])
	assert.NotNil(t, record["total_latency"])
	assert.NotNil(t, record["upstream_latency"])
}

func TestNewRecordWithRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)

	record := NewRecord().WithRequest(req).Fields()

	assert.Equal(t, req.Host, record["host"])
	assert.Equal(t, req.Method, record["method"])
	assert.Equal(t, req.Proto, record["protocol"])
	assert.Equal(t, req.UserAgent(), record["user_agent"])
}

func TestNewRecordWithResponse(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := NewRecord().WithResponse(resp).Fields()

	assert.Equal(t, resp.StatusCode, record["status_code"])
	assert.NotNil(t, record["status_code"])
}

func TestNewRecordField(t *testing.T) {
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/path?userid=1", nil)
	req.RemoteAddr = "0.0.0.0"
	req.Header.Set("User-Agent", "user-agent")

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := NewRecord().WithClientIP(req).WithLatency(latency).WithRequest(req).WithRequestURI(req).WithResponse(resp).WithUpstreamAddress(req).WithUpstreamURI(req).Fields()

	assert.Equal(t, "access-log", record["prefix"])

	// WithClientIP
	assert.Equal(t, request.RealIP(req), record["client_ip"])
	assert.Equal(t, "0.0.0.0", record["client_remote_addr"])

	// WithLatency
	assert.Equal(t, int64(99), record["total_latency"])
	assert.Equal(t, int64(101), record["upstream_latency"])

	// WithRequest
	assert.Equal(t, "example.com", record["host"])
	assert.Equal(t, http.MethodGet, record["method"])
	assert.Equal(t, "HTTP/1.1", record["protocol"])
	assert.Equal(t, "user-agent", record["user_agent"])

	// WithRequest URI
	assert.Equal(t, "", record["request_uri"])

	// WithResponse
	assert.Equal(t, http.StatusOK, record["status_code"])

	// WithUpstreamAddress
	assert.Equal(t, "http://example.com/path", record["upstream_address"])

	// WithUpstreamURI
	assert.Equal(t, "/path?userid=1", record["upstream_uri"])
}
