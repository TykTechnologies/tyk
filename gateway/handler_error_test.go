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

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
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

func TestHandleDefaultErrorSoapXml(t *testing.T) {

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
			header.ContentType: header.ApplicationSoapXML,
		},
		BodyMatchFunc: func(b []byte) bool {
			return strings.TrimSpace(expect) == string(bytes.TrimSpace(b))
		},
	})

	ts.Run(t, test.TestCase{
		Path: "/",
		Code: http.StatusInternalServerError,
		Headers: map[string]string{
			header.ContentType: header.ApplicationSoapXML + "; charset=UTF-8",
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

func TestErrorHandler_AnalyticsRecordsOverriddenStatusCode(t *testing.T) {
	t.Run("analytics records overridden status code not original", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AnalyticsConfig.EnableDetailedRecording = true
			// Configure error override: 401 -> 403
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 403, // Override to 403
							Body:       `{"error": "access_denied", "code": "FORBIDDEN"}`,
							Message:    "Access denied",
						},
					},
				},
			}
		})
		defer ts.Close()

		// Clear any existing analytics records
		ts.Gw.Analytics.Flush()
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		// Create an API that requires authentication
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-override/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false // Require auth
			spec.Auth.AuthHeaderName = "Authorization"
		})

		// Send request without auth - should trigger 401, but override returns 403
		_, _ = ts.Run(t, test.TestCase{
			Path: "/test-override/get",
			Code: http.StatusForbidden, // Expect overridden code
		})

		// Let records be sent
		ts.Gw.Analytics.Flush()

		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
		require.Len(t, results, 1, "Should return 1 record")

		var record analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
		require.NoError(t, err)

		// Key assertion: analytics should record the OVERRIDDEN status code (403), not original (401)
		assert.Equal(t, http.StatusForbidden, record.ResponseCode,
			"Analytics should record overridden status code (403), not original (401)")
	})

	t.Run("analytics records original code when no override matches", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AnalyticsConfig.EnableDetailedRecording = true
			// Configure error override only for 500
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"500": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 503,
							Message:    "Service unavailable",
						},
					},
				},
			}
		})
		defer ts.Close()

		// Clear any existing analytics records
		ts.Gw.Analytics.Flush()
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		// Create an API that requires authentication
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-no-override/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"
		})

		// Send request without auth - should trigger 401 (no override configured for 401)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/test-no-override/get",
			Code: http.StatusUnauthorized, // No override, expect original code
		})

		// Let records be sent
		ts.Gw.Analytics.Flush()

		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
		require.Len(t, results, 1, "Should return 1 record")

		var record analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
		require.NoError(t, err)

		// No override matched, so analytics should record original status code
		assert.Equal(t, http.StatusUnauthorized, record.ResponseCode,
			"Analytics should record original status code when no override matches")
	})
}

func TestErrorHandler_APILevelErrorOverrides(t *testing.T) {
	t.Run("API-level override takes precedence over gateway-level", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 403,
							Body:       `{"error": "gateway_override"}`,
						},
					},
				},
			}
		})
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api-override/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"

			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 418,
							Body:       `{"error": "api_override"}`,
						},
					},
				},
			}
		})

		ts.Run(t, test.TestCase{
			Path: "/test-api-override/get",
			Code: http.StatusTeapot,
			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), "api_override")
			},
		})
	})

	t.Run("Gateway-level fallback when API-level has no match", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 403,
							Body:       `{"error": "gateway_override"}`,
						},
					},
				},
			}
		})
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-fallback/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"

			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"500": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 503,
							Body:       `{"error": "api_override"}`,
						},
					},
				},
			}
		})

		ts.Run(t, test.TestCase{
			Path: "/test-fallback/get",
			Code: http.StatusForbidden,
			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), "gateway_override")
			},
		})
	})

	t.Run("API-level override works without gateway-level overrides", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api-only/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"

			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 418,
							Body:       `{"error": "api_override_only"}`,
						},
					},
				},
			}
		})

		ts.Run(t, test.TestCase{
			Path: "/test-api-only/get",
			Code: http.StatusTeapot,
			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), "api_override_only")
			},
		})
	})

	t.Run("OAS API-level override", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-oas-override/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"
			spec.IsOAS = true

			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 418,
							Body:       `{"error": "oas_api_override"}`,
						},
					},
				},
			}

			spec.OAS = oas.OAS{
				T: openapi3.T{
					OpenAPI: "3.0.3",
					Info: &openapi3.Info{
						Title:   "OAS API",
						Version: "1",
					},
					Paths: openapi3.NewPaths(
						openapi3.WithPath("/get", &openapi3.PathItem{
							Get: &openapi3.Operation{
								Responses: openapi3.NewResponses(),
							},
						}),
					),
				},
			}
		})

		ts.Run(t, test.TestCase{
			Path: "/test-oas-override/get",
			Code: http.StatusTeapot,
			BodyMatchFunc: func(b []byte) bool {
				return strings.Contains(string(b), "oas_api_override")
			},
		})
	})

	t.Run("skips error override when API-level override is disabled", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test-api-only/"
			spec.Proxy.TargetURL = "http://httpbin.org"
			spec.UseKeylessAccess = false
			spec.Auth.AuthHeaderName = "Authorization"

			spec.ErrorOverrides = apidef.ErrorOverridesMap{
				"401": []apidef.ErrorOverride{
					{
						Response: apidef.ErrorResponse{
							StatusCode: 418,
							Body:       `{"error": "api_override_only"}`,
						},
					},
				},
			}
			spec.ErrorOverridesDisabled = true
		})

		ts.Run(t, test.TestCase{
			Path: "/test-api-only/get",
			Code: 401,
		})
	})
}
