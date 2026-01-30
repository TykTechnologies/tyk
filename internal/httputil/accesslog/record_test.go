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

func TestRecord_WithCacheHit(t *testing.T) {
	testCases := []struct {
		name     string
		cacheHit bool
		want     bool
	}{
		{
			name:     "cache hit is true when response served from cache",
			cacheHit: true,
			want:     true,
		},
		{
			name:     "cache hit is false when response not served from cache",
			cacheHit: false,
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			record := accesslog.NewRecord()
			record.WithCacheHit(tc.cacheHit)

			got := record.Fields(nil)

			assert.Equal(t, tc.want, got["cache_hit"])
		})
	}
}

func TestRecord_WithCacheHit_FullRecord(t *testing.T) {
	testCases := []struct {
		name     string
		cacheHit bool
	}{
		{
			name:     "full record with cache hit true",
			cacheHit: true,
		},
		{
			name:     "full record with cache hit false",
			cacheHit: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			latency := analytics.Latency{
				Total:    100,
				Upstream: 80,
				Gateway:  20,
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/resource", nil)
			req.RemoteAddr = "192.168.1.1"
			req.Header.Set("User-Agent", "test-agent")

			resp := &http.Response{
				StatusCode: http.StatusOK,
			}

			record := accesslog.NewRecord()
			record.WithRequest(req, latency)
			record.WithResponse(resp)
			record.WithCacheHit(tc.cacheHit)

			got := record.Fields(nil)

			// Verify cache_hit field is present and has correct value
			assert.Equal(t, tc.cacheHit, got["cache_hit"])

			// Verify other fields are still present
			assert.Equal(t, http.MethodGet, got["method"])
			assert.Equal(t, "/api/v1/resource", got["path"])
			assert.Equal(t, http.StatusOK, got["status"])
		})
	}
}
