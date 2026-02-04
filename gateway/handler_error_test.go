package gateway

import (
	"bytes"
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
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
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
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
		}))
		defer upstream.Close()

		// Configure a 1 second timeout via global config
		ts := StartTest(func(c *config.Config) {
			c.ProxyDefaultTimeout = 1
			c.AnalyticsConfig.EnableDetailedRecording = true
		})
		defer ts.Close()

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
