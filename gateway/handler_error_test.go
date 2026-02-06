package gateway

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/test"
)

func (s *Test) TestHandleError_text_xml(t *testing.T) {
	file := filepath.Join(s.Gw.GetConfig().TemplatePath, "error_500.xml")
	xml := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>{{.Message}}</message>
</error>`
	err := ioutil.WriteFile(file, []byte(xml), 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>
	<code>500</code>
	<message>There was a problem proxying the request</message>
</error>`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorXml(t *testing.T) {

	expect := `<?xml version = "1.0" encoding = "UTF-8"?>
<error>There was a problem proxying the request</error>`
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.TextXML + "; charset=UTF-8",
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})
}

func TestHandleDefaultErrorJSON(t *testing.T) {

	expect := `
{
    "error": "There was a problem proxying the request"
}
`

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})
	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.ApplicationJSON,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

}

func TestErrorHandler_LatencyRecording(t *testing.T) {
	t.Run("connection refused error has correct latency structure", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AnalyticsConfig.EnableDetailedRecording = true
		})
		defer ts.Close()

		// Clear any existing analytics records from previous tests
		ts.Gw.Analytics.Flush()
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		// Use unreachable host to trigger ErrorHandler via connection refused
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://localhost:66666" // Connection refused
		})

		_, _ = ts.Run(t, test.TestCase{
			Path: "/",
			Code: http.StatusInternalServerError,
		})

		// let records to be sent
		ts.Gw.Analytics.Flush()

		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
		require.Len(t, results, 1, "Should return 1 record")

		var record analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
		require.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, record.ResponseCode)
		// For connection refused errors, latency is sub-millisecond and may be 0ms
		// The important invariants are:
		assert.Zero(t, record.Latency.Upstream, "Upstream should be zero - no upstream response")
		assert.Equal(t, record.Latency.Total, record.Latency.Gateway, "Gateway should equal Total for connection errors")
		assert.Equal(t, record.Latency.Total, record.RequestTime, "RequestTime should equal Total")
	})

	t.Run("504 timeout records timeout duration", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Second)
		}))
		defer upstream.Close()

		// Configure a 1 second timeout via global config
		ts := StartTest(func(c *config.Config) {
			c.ProxyDefaultTimeout = 1
			c.AnalyticsConfig.EnableDetailedRecording = true
		})
		defer ts.Close()

		// Clear any existing analytics records from previous tests
		ts.Gw.Analytics.Flush()
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = upstream.URL
		})

		_, _ = ts.Run(t, test.TestCase{
			Path: "/",
			Code: http.StatusGatewayTimeout,
		})

		// let records to be sent
		ts.Gw.Analytics.Flush()

		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
		require.Len(t, results, 1, "Should return 1 record")

		var record analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
		require.NoError(t, err)

		assert.Equal(t, http.StatusGatewayTimeout, record.ResponseCode)
		assert.GreaterOrEqual(t, record.Latency.Total, int64(1000), "Should be at least 1000ms")
		assert.Zero(t, record.Latency.Upstream, "Upstream should be zero")
	})

	t.Run("latency invariants hold for error responses", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AnalyticsConfig.EnableDetailedRecording = true
		})
		defer ts.Close()

		// Clear any existing analytics records
		ts.Gw.Analytics.Flush()
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://localhost:66666"
		})

		_, _ = ts.Run(t, test.TestCase{Path: "/", Code: 500})

		// let records to be sent
		ts.Gw.Analytics.Flush()

		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
		require.Len(t, results, 1, "Should return 1 record")

		var record analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
		require.NoError(t, err)

		// Key invariants that must hold for error responses:
		// 1. RequestTime equals Total latency
		assert.Equal(t, record.RequestTime, record.Latency.Total, "RequestTime should equal Total latency")
		// 2. Gateway = Total - Upstream (for errors, Upstream is 0, so Gateway = Total)
		assert.Equal(t, record.Latency.Gateway, record.Latency.Total-record.Latency.Upstream)
		// 3. Upstream is 0 for connection errors
		assert.Zero(t, record.Latency.Upstream, "Upstream should be zero for connection errors")
	})
}

func TestErrorHandler_BackwardCompatibility_WriteResponseTrue(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = "http://localhost:66666"
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
	})

	ts.Gw.Analytics.Flush()

	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1)

	var record analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
	require.NoError(t, err)

	assert.Equal(t, http.StatusInternalServerError, record.ResponseCode)
	assert.NotEmpty(t, record.RawResponse)

	decoded, err := base64.StdEncoding.DecodeString(record.RawResponse)
	require.NoError(t, err)

	rawResponse := string(decoded)
	assert.Contains(t, rawResponse, "HTTP/")
	assert.Contains(t, rawResponse, "500")
	assert.Contains(t, rawResponse, "Content-Type")
}

func TestErrorHandler_BackwardCompatibility_WriteResponseFalse(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "test-api",
			OrgID:  "test-org",
			Name:   "Test API",
			Proxy:  apidef.ProxyConfig{},
			Domain: "",
		},
		GlobalConfig: ts.Gw.GetConfig(),
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctxSetRequestStartTime(r, time.Now())

	handler.HandleError(w, r, "Test error", http.StatusForbidden, false)

	ts.Gw.Analytics.Flush()

	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1, "Analytics must be recorded even when writeResponse=false")

	var record analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, record.ResponseCode)
	assert.Equal(t, "", w.Body.String(), "No response should be written when writeResponse=false")
}

func TestErrorHandler_BackwardCompatibility_AccessLogStatusCode(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AccessLogs.Enabled = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "test-api",
			OrgID:  "test-org",
			Name:   "Test API",
			Proxy:  apidef.ProxyConfig{},
			Domain: "",
		},
		GlobalConfig: ts.Gw.GetConfig(),
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	t.Run("writeResponse=true results in StatusCode=errCode for access log", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctxSetRequestStartTime(r, time.Now())

		handler.HandleError(w, r, "Test error", http.StatusForbidden, true)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestErrorHandler_BackwardCompatibility_MCPNonJSONRPC(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "test-api",
			OrgID:  "test-org",
			Name:   "Test API",
			Proxy:  apidef.ProxyConfig{},
			Domain: "",
		},
		GlobalConfig: ts.Gw.GetConfig(),
	}
	spec.MarkAsMCP()

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctxSetRequestStartTime(r, time.Now())

	handler.HandleError(w, r, "Test error", http.StatusForbidden, true)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "jsonrpc")
	assert.Contains(t, w.Body.String(), "error")

	ts.Gw.Analytics.Flush()

	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1)

	var record analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, record.ResponseCode)
}

func TestErrorHandler_BackwardCompatibility_DoNotTrack(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:      "test-api",
			OrgID:      "test-org",
			Name:       "Test API",
			Proxy:      apidef.ProxyConfig{},
			Domain:     "",
			DoNotTrack: true,
		},
		GlobalConfig: ts.Gw.GetConfig(),
	}

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctxSetRequestStartTime(r, time.Now())

	handler.HandleError(w, r, "Test error", http.StatusForbidden, true)

	ts.Gw.Analytics.Flush()

	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	assert.Len(t, results, 0, "No analytics should be recorded when DoNotTrack=true")
}

func TestErrorHandler_JSONRPCStillWorks(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:          "test-api",
			OrgID:          "test-org",
			Name:           "Test API",
			Proxy:          apidef.ProxyConfig{},
			Domain:         "",
			JsonRpcVersion: apidef.JsonRPC20,
		},
		GlobalConfig: ts.Gw.GetConfig(),
	}
	spec.MarkAsMCP()

	handler := ErrorHandler{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)
	ctxSetRequestStartTime(r, time.Now())

	state := &httpctx.JSONRPCRoutingState{
		ID: "test-123",
	}
	httpctx.SetJSONRPCRoutingState(r, state)

	handler.HandleError(w, r, "Access denied", http.StatusForbidden, true)

	assert.Equal(t, http.StatusForbidden, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "jsonrpc")
	assert.Contains(t, body, "2.0")
	assert.Contains(t, body, "test-123")

	ts.Gw.Analytics.Flush()

	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1)

	var record analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
	require.NoError(t, err)

	assert.Equal(t, http.StatusForbidden, record.ResponseCode)

	decoded, err := base64.StdEncoding.DecodeString(record.RawResponse)
	require.NoError(t, err)

	rawResponse := string(decoded)
	assert.Contains(t, rawResponse, "HTTP/", "RawResponse should contain full HTTP response")
	assert.True(t, strings.HasPrefix(rawResponse, "HTTP/"), "RawResponse should start with HTTP status line")
}
