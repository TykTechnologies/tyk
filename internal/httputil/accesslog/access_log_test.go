package accesslog

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/request"
)

func TestNewRecord(t *testing.T) {
	apiID := "api_id"
	orgID := "org_id"

	record := NewRecord(apiID, orgID).Fields()

	assert.Equal(t, apiID, record["APIID"])
	assert.Equal(t, orgID, record["OrgID"])
	assert.NotNil(t, record["APIID"])
	assert.NotNil(t, record["OrgID"])
}

func TestNewRecordWithLatency(t *testing.T) {
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}

	record := NewRecord("api_id", "org_id").WithLatency(latency).Fields()

	assert.Equal(t, latency.Total, record["TotalLatency"])
	assert.Equal(t, latency.Upstream, record["UpstreamLatency"])
	assert.NotNil(t, record["TotalLatency"])
	assert.NotNil(t, record["UpstreamLatency"])
}

func TestNewRecordWithRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)

	record := NewRecord("api_id", "org_id").WithRequest(req).Fields()

	assert.Equal(t, request.RealIP(req), record["ClientIP"])
	assert.Equal(t, req.RemoteAddr, record["ClientRemoteAddr"])
	assert.Equal(t, req.Host, record["Host"])
	assert.Equal(t, req.Method, record["Method"])
	assert.Equal(t, req.Proto, record["Proto"])
	assert.Equal(t, req.RequestURI, record["RequestURI"])
	assert.Equal(t, req.URL.Path, record["UpstreamAddress"])
	assert.Equal(t, req.URL.Path, record["UpstreamPath"])
	assert.Equal(t, req.URL.RequestURI(), record["UpstreamURI"])
	assert.Equal(t, req.UserAgent(), record["UserAgent"])
}

func TestNewRecordWithResponse(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
	}

	record := NewRecord("api_id", "org_id").WithResponse(resp).Fields()

	assert.Equal(t, resp.StatusCode, record["StatusCode"])
	assert.NotNil(t, record["StatusCode"])
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

	record := NewRecord("api_id", "org_id").WithLatency(latency).WithRequest(req).WithResponse(resp).Fields()

	assert.Equal(t, "api_id", record["APIID"])
	assert.Equal(t, "org_id", record["OrgID"])
	assert.Equal(t, "access-log", record["prefix"])
	assert.Equal(t, int64(99), record["TotalLatency"])
	assert.Equal(t, int64(101), record["UpstreamLatency"])
	assert.Equal(t, request.RealIP(req), record["ClientIP"])
	assert.Equal(t, "0.0.0.0", record["ClientRemoteAddr"])
	assert.Equal(t, "example.com", record["Host"])
	assert.Equal(t, http.MethodGet, record["Method"])
	assert.Equal(t, "HTTP/1.1", record["Proto"])
	assert.Equal(t, "", record["RequestURI"])
	assert.Equal(t, "http://example.com/path?userid=1", record["UpstreamAddress"])
	assert.Equal(t, "/path", record["UpstreamPath"])
	assert.Equal(t, "/path?userid=1", record["UpstreamURI"])
	assert.Equal(t, "user-agent", record["UserAgent"])
	assert.Equal(t, http.StatusOK, record["StatusCode"])
}
