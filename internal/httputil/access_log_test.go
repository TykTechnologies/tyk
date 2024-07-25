package httputil

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/request"
)

func TestNewAccessLogRecord(t *testing.T) {
	apiID := "api_id"
	apiKey := "api_key"
	orgID := "org_id"

	accessLogRecord := NewAccessLogRecord(apiID, apiKey, orgID)

	assert.Equal(t, apiID, accessLogRecord.APIID)
	assert.NotNil(t, accessLogRecord.APIID)
	assert.Equal(t, apiKey, accessLogRecord.APIKey)
	assert.NotNil(t, accessLogRecord.APIKey)
	assert.Equal(t, orgID, accessLogRecord.OrgID)
	assert.NotNil(t, accessLogRecord.OrgID)
	assert.Nil(t, accessLogRecord.Latency)
	assert.Nil(t, accessLogRecord.Request)
	assert.Nil(t, accessLogRecord.Response)
}

func TestNewAccessLogRecordWithLatency(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	latency := &analytics.Latency{
		Total:    99,
		Upstream: 101,
	}
	accessLogRecord.WithLatency(latency)

	assert.Equal(t, latency, accessLogRecord.Latency)
	assert.NotNil(t, accessLogRecord.Latency)
}

func TestNewAccessLogRecordWithRequest(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	accessLogRecord.WithRequest(req)

	assert.Equal(t, req, accessLogRecord.Request)
	assert.NotNil(t, accessLogRecord.Request)
}

func TestNewAccessLogRecordWithResponse(t *testing.T) {
	accessLogRecord := NewAccessLogRecord("api_id", "api_key", "org_id")
	resp := &http.Response{
		StatusCode: http.StatusOK,
	}
	accessLogRecord.WithResponse(resp)

	assert.Equal(t, resp, accessLogRecord.Response)
	assert.NotNil(t, accessLogRecord.Response)
}

func TestNewAccessLogRecordLogger(t *testing.T) {
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

	log := logrus.New()
	logger := accessLogRecord.Logger(log)

	assert.Equal(t, "api_id", logger.Data["APIID"])
	assert.Equal(t, "api_key", logger.Data["APIKey"])
	assert.Equal(t, "org_id", logger.Data["OrgID"])
	assert.Equal(t, "access-log", logger.Data["prefix"])

	assert.Equal(t, int64(99), logger.Data["TotalLatency"])
	assert.Equal(t, int64(101), logger.Data["UpstreamLatency"])

	assert.Equal(t, request.RealIP(req), logger.Data["ClientIP"])
	assert.Equal(t, "0.0.0.0", logger.Data["ClientRemoteAddr"])
	assert.Equal(t, "example.com", logger.Data["Host"])
	assert.Equal(t, http.MethodGet, logger.Data["Method"])
	assert.Equal(t, "HTTP/1.1", logger.Data["Proto"])
	assert.Equal(t, "", logger.Data["RequestURI"])
	assert.Equal(t, "http://example.com/path?userid=1", logger.Data["UpstreamAddress"])
	assert.Equal(t, "/path", logger.Data["UpstreamPath"])
	assert.Equal(t, "/path?userid=1", logger.Data["UpstreamURI"])
	assert.Equal(t, "user-agent", logger.Data["UserAgent"])

	assert.Equal(t, http.StatusOK, logger.Data["StatusCode"])
}
