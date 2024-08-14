package httputil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/request"
)

func TestNewAccessLogRecord(t *testing.T) {
	apiID := "api_id"
	apiKey := "api_key"
	orgID := "org_id"

	accessLogRecord := NewAccessLogRecord(apiID, apiKey, orgID)

	assert.Equal(t, apiID, (*accessLogRecord)["APIID"])
	assert.Equal(t, apiKey, (*accessLogRecord)["APIKey"])
	assert.Equal(t, orgID, (*accessLogRecord)["OrgID"])
	assert.NotNil(t, (*accessLogRecord)["APIID"])
	assert.NotNil(t, (*accessLogRecord)["APIKey"])
	assert.NotNil(t, (*accessLogRecord)["OrgID"])
}

func TestNewAccessLogRecordWithLatency(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}
	accessLogRecord.WithLatency(latency)

	assert.Equal(t, latency.Total, (*accessLogRecord)["TotalLatency"])
	assert.Equal(t, latency.Upstream, (*accessLogRecord)["UpstreamLatency"])
	assert.NotNil(t, (*accessLogRecord)["TotalLatency"])
	assert.NotNil(t, (*accessLogRecord)["UpstreamLatency"])
}

func TestNewAccessLogRecordWithRequest(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	accessLogRecord.WithRequest(req)

	assert.Equal(t, request.RealIP(req), (*accessLogRecord)["ClientIP"])
	assert.Equal(t, req.RemoteAddr, (*accessLogRecord)["ClientRemoteAddr"])
	assert.Equal(t, req.Host, (*accessLogRecord)["Host"])
	assert.Equal(t, req.Method, (*accessLogRecord)["Method"])
	assert.Equal(t, req.Proto, (*accessLogRecord)["Proto"])
	assert.Equal(t, req.RequestURI, (*accessLogRecord)["RequestURI"])
	assert.Equal(t, req.URL.Scheme+"://"+req.URL.Host+req.URL.RequestURI(), (*accessLogRecord)["UpstreamAddress"])
	assert.Equal(t, req.URL.Path, (*accessLogRecord)["UpstreamPath"])
	assert.Equal(t, req.URL.RequestURI(), (*accessLogRecord)["UpstreamURI"])
	assert.Equal(t, req.UserAgent(), (*accessLogRecord)["UserAgent"])
}

func TestNewAccessLogRecordWithResponse(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	resp := &http.Response{
		StatusCode: http.StatusOK,
	}
	accessLogRecord.WithResponse(resp)

	assert.Equal(t, resp.StatusCode, (*accessLogRecord)["StatusCode"])
	assert.NotNil(t, (*accessLogRecord)["StatusCode"])
}

func TestNewAccessLogRecordField(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")

	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}
	accessLogRecord.WithLatency(latency)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/path?userid=1", nil)
	req.RemoteAddr = "0.0.0.0"
	req.Header.Set("User-Agent", "user-agent")
	accessLogRecord.WithRequest(req)

	resp := &http.Response{
		StatusCode: http.StatusOK,
	}
	accessLogRecord.WithResponse(resp)
	fields := accessLogRecord.Fields()

	assert.Equal(t, "api_id", fields["APIID"])
	assert.Equal(t, "api_key", fields["APIKey"])
	assert.Equal(t, "org_id", fields["OrgID"])
	assert.Equal(t, "access-log", fields["prefix"])
	assert.Equal(t, int64(99), fields["TotalLatency"])
	assert.Equal(t, int64(101), fields["UpstreamLatency"])
	assert.Equal(t, request.RealIP(req), fields["ClientIP"])
	assert.Equal(t, "0.0.0.0", fields["ClientRemoteAddr"])
	assert.Equal(t, "example.com", fields["Host"])
	assert.Equal(t, http.MethodGet, fields["Method"])
	assert.Equal(t, "HTTP/1.1", fields["Proto"])
	assert.Equal(t, "", fields["RequestURI"])
	assert.Equal(t, "http://example.com/path?userid=1", fields["UpstreamAddress"])
	assert.Equal(t, "/path", fields["UpstreamPath"])
	assert.Equal(t, "/path?userid=1", fields["UpstreamURI"])
	assert.Equal(t, "user-agent", fields["UserAgent"])
	assert.Equal(t, http.StatusOK, fields["StatusCode"])
}
