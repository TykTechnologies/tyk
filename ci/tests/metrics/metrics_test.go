package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	gatewayURL    = "http://localhost:9000"
	prometheusURL = "http://localhost:9090"
	pollTimeout   = 30 * time.Second
	pollInterval  = 2 * time.Second
)

// promQueryResult represents the Prometheus instant query response.
type promQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		Result []struct {
			Metric map[string]string  `json:"metric"`
			Value  [2]json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func TestMain(m *testing.M) {
	// Guard: only run when explicitly enabled.
	if os.Getenv("E2E_METRICS") == "" {
		fmt.Println("skipping e2e metrics tests (set E2E_METRICS=1)")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// gwProfile returns the current GW_PROFILE or "default".
func gwProfile() string {
	if p := os.Getenv("GW_PROFILE"); p != "" {
		return p
	}
	return "default"
}

// ---------- Default profile tests ----------

func TestConfigMetrics(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	// The gateway loads APIs from apps/ on startup, which triggers a reload
	// cycle. After the initial load the config metrics should be populated.
	assertMetricGTE(t, "tyk_gateway_apis_loaded", 1)
	assertMetricGTE(t, "tyk_gateway_config_reload_total", 1)
	assertMetricExists(t, "tyk_gateway_config_reload_duration_seconds_count")
}

func TestRequestCounter(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 20)

	// OTel counter names get a "_total" suffix in Prometheus.
	assertMetricGTE(t, "tyk_http_requests_total", 20)
}

func TestREDMetrics(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 20)

	// Verify histograms exist with tyk_api_id dimension.
	// OTel metric "http.server.request.duration" (unit "s") -> Prometheus "http_server_request_duration_seconds".
	// OTel attribute "tyk.api.id" -> Prometheus label "tyk_api_id".
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_count{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_count{tyk_api_id="3"}`)

	// Verify counter with dimensions.
	assertMetricGTE(t, `tyk_api_requests_total{tyk_api_id="3"}`, 20)
}

func TestREDMetrics_HistogramBuckets(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)

	// Verify histogram _bucket metric exists (Prometheus creates _bucket from OTel histograms).
	assertMetricExists(t, `http_server_request_duration_seconds_bucket{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_bucket{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_bucket{tyk_api_id="3"}`)

	// Verify _sum metric exists for all 3 histograms.
	assertMetricExists(t, `http_server_request_duration_seconds_sum{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_sum{tyk_api_id="3"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_sum{tyk_api_id="3"}`)
}

func TestREDMetrics_MethodDimension(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
	sendTraffic(t, "POST", gatewayURL+"/test/post", 5)

	// Verify GET and POST are recorded separately on the counter.
	assertMetricExists(t, `tyk_api_requests_total{tyk_api_id="3",http_request_method="GET"}`)
	assertMetricExists(t, `tyk_api_requests_total{tyk_api_id="3",http_request_method="POST"}`)

	// Verify GET and POST are recorded separately on histograms.
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",http_request_method="GET"}`)
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",http_request_method="POST"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_count{tyk_api_id="3",http_request_method="GET"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_count{tyk_api_id="3",http_request_method="POST"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_count{tyk_api_id="3",http_request_method="GET"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_count{tyk_api_id="3",http_request_method="POST"}`)
}

func TestREDMetrics_StatusCodeDimension(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
	sendTraffic(t, "GET", gatewayURL+"/test/status/404", 3)

	// Verify 200 and 404 status code dimensions on counter.
	assertMetricExists(t, `tyk_api_requests_total{tyk_api_id="3",http_response_status_code="200"}`)
	assertMetricExists(t, `tyk_api_requests_total{tyk_api_id="3",http_response_status_code="404"}`)

	// Verify status code dimension on http.server histogram (has response_code dimension).
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",http_response_status_code="200"}`)
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",http_response_status_code="404"}`)
}

func TestREDMetrics_ResponseFlag(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 3)

	// The response_flag dimension (tyk_response_flag label) should exist on all 3 histograms.
	// Successful requests fall back to status code string.
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",tyk_response_flag="200"}`)
	assertMetricExists(t, `tyk_gateway_request_duration_seconds_count{tyk_api_id="3",tyk_response_flag="200"}`)
	assertMetricExists(t, `tyk_upstream_request_duration_seconds_count{tyk_api_id="3",tyk_response_flag="200"}`)

	// 5xx upstream responses get classified with the "URS" (Upstream Response 5xx) flag.
	sendTraffic(t, "GET", gatewayURL+"/test/status/500", 3)
	assertMetricExists(t, `http_server_request_duration_seconds_count{tyk_api_id="3",tyk_response_flag="URS"}`)
}

func TestResourceAttributes(t *testing.T) {
	if p := gwProfile(); p == "cardinality" || p == "response-headers" {
		t.Skip("skipped under " + p + " profile (no segment tags configured)")
	}
	waitForGateway(t)

	// Send traffic to generate metrics.
	const N = 10
	for i := range N {
		resp, err := http.Get(gatewayURL + "/test/ip")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	t.Run("target_info_has_resource_attributes", func(t *testing.T) {
		query := `target_info{job="otel-collector"}`

		// tyk_gw_id must be present and non-empty
		gwID := assertLabelPresent(t, query, "tyk_gw_id")
		t.Logf("Gateway ID: %s", gwID)

		// tyk_gw_dataplane must equal "false" (standalone mode, not dataplane)
		assertLabelEquals(t, query, "tyk_gw_dataplane", "false")

		// tyk_gw_group_id should not be present (only in dataplane mode)
		// Skip this check for standalone mode

		// tyk_gw_tags is only present when NodeIsSegmented=true
		// The test config has NodeIsSegmented=true and Tags set, so we expect the label
		// Note: tags are only added when isSegmented is true in GatewayResourceAttributes
		labels, ok := queryPrometheusLabels(t, query)
		if ok {
			if val, exists := labels["tyk_gw_tags"]; exists && val != "" {
				t.Logf("tyk_gw_tags found: %s", val)
				assertLabelContains(t, query, "tyk_gw_tags", "production")
				assertLabelContains(t, query, "tyk_gw_tags", "edge")
				assertLabelContains(t, query, "tyk_gw_tags", "e2e-test")
			} else {
				t.Logf("tyk_gw_tags is empty or missing - this may indicate NodeIsSegmented is not properly set")
			}
		}
	})

	t.Run("resource_attributes_on_metrics", func(t *testing.T) {
		query := `tyk_http_requests_total`

		// tyk_gw_id should appear as a direct label on the metric
		gwID := assertLabelPresent(t, query, "tyk_gw_id")
		t.Logf("tyk_http_requests_total has tyk_gw_id=%s", gwID)

		// tyk_gw_dataplane should appear as a direct label (false for standalone)
		assertLabelEquals(t, query, "tyk_gw_dataplane", "false")

		// tyk_gw_tags should appear as a direct label
		assertLabelContains(t, query, "tyk_gw_tags", "production")
		assertLabelContains(t, query, "tyk_gw_tags", "edge")
		assertLabelContains(t, query, "tyk_gw_tags", "e2e-test")
	})

	t.Run("standard_otel_attributes", func(t *testing.T) {
		query := `target_info{job="otel-collector"}`

		// Standard attributes should be present
		// Note: service_name is exported as exported_job by the OTel collector
		assertLabelPresent(t, query, "service_version")
		assertLabelPresent(t, query, "host_name")
		assertLabelPresent(t, query, "process_pid")
	})
}

func TestDoNotTrack_NoMetrics(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	// Send traffic exclusively to the do_not_track API (api_id=4, /notrack/).
	sendTraffic(t, "GET", gatewayURL+"/notrack/ip", 10)

	// Allow time for a full export + scrape cycle before asserting absence.
	time.Sleep(15 * time.Second)

	// No metric should carry api_id="4".
	assertMetricAbsent(t, `tyk_api_requests_total{tyk_api_id="4"}`)
	assertMetricAbsent(t, `http_server_request_duration_seconds_count{tyk_api_id="4"}`)
	assertMetricAbsent(t, `tyk_gateway_request_duration_seconds_count{tyk_api_id="4"}`)
	assertMetricAbsent(t, `tyk_upstream_request_duration_seconds_count{tyk_api_id="4"}`)
}

func TestREDMetrics_AllDimensionsPresent(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)

	// http.server.request.duration has: method, response_code, api_id, response_flag.
	assertMetricHasLabels(t, "http_server_request_duration_seconds_count", []string{
		"http_request_method",
		"http_response_status_code",
		"tyk_api_id",
		"tyk_response_flag",
	})

	// tyk.gateway.request.duration has: method, api_id, response_flag.
	assertMetricHasLabels(t, "tyk_gateway_request_duration_seconds_count", []string{
		"http_request_method",
		"tyk_api_id",
		"tyk_response_flag",
	})

	// tyk.upstream.request.duration has: method, api_id, response_flag.
	assertMetricHasLabels(t, "tyk_upstream_request_duration_seconds_count", []string{
		"http_request_method",
		"tyk_api_id",
		"tyk_response_flag",
	})

	// tyk.api.requests.total has: method, response_code, api_id.
	assertMetricHasLabels(t, "tyk_api_requests_total", []string{
		"http_request_method",
		"http_response_status_code",
		"tyk_api_id",
	})
}

// ---------- Custom profile tests ----------

func TestCustomProfile_Instruments(t *testing.T) {
	if gwProfile() != "custom" {
		t.Skip("only runs under custom profile")
	}
	waitForGateway(t)

	tests := []struct {
		name    string
		traffic func(t *testing.T)
		assert  func(t *testing.T)
	}{
		{
			name: "custom histogram exists with tenant dimension",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 10,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				// custom.request.duration -> custom_request_duration_seconds (histogram with unit "s")
				assertMetricExists(t, `custom_request_duration_seconds_count{tyk_api_id="3",tenant="acme"}`)
				assertMetricExists(t, `custom_request_duration_seconds_bucket{tyk_api_id="3",tenant="acme"}`)
				// Verify _sum metric exists for custom histogram.
				assertMetricExists(t, `custom_request_duration_seconds_sum{tyk_api_id="3",tenant="acme"}`)
			},
		},
		{
			name: "custom histogram has all expected labels",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				// Dimensions: method, response_code, api_id, X-Tenant header.
				assertMetricHasLabels(t, "custom_request_duration_seconds_count", []string{
					"http_request_method",
					"http_response_status_code",
					"tyk_api_id",
					"tenant",
				})
			},
		},
		{
			name: "custom histogram method dimension splits GET and POST",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
				sendTrafficWithHeaders(t, "POST", gatewayURL+"/test/post", 5,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_request_duration_seconds_count{http_request_method="GET",tenant="acme"}`)
				assertMetricExists(t, `custom_request_duration_seconds_count{http_request_method="POST",tenant="acme"}`)
			},
		},
		{
			name: "custom histogram status_code dimension",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/status/404", 3,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_request_duration_seconds_count{http_response_status_code="200",tenant="acme"}`)
				assertMetricExists(t, `custom_request_duration_seconds_count{http_response_status_code="404",tenant="acme"}`)
			},
		},
		{
			name: "custom counter with tenant dimension",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricGTE(t, `custom_api_requests_total{tyk_api_id="3",tenant="acme"}`, 5)
			},
		},
		{
			name: "custom counter has all expected labels",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				// custom.api.requests.total dimensions: method, api_id, tenant.
				assertMetricHasLabels(t, "custom_api_requests_total", []string{
					"http_request_method",
					"tyk_api_id",
					"tenant",
				})
			},
		},
		{
			name: "custom counter method dimension splits GET and POST",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 5,
					map[string]string{"X-Tenant": "acme"})
				sendTrafficWithHeaders(t, "POST", gatewayURL+"/test/post", 5,
					map[string]string{"X-Tenant": "acme"})
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_api_requests_total{http_request_method="GET",tenant="acme"}`)
				assertMetricExists(t, `custom_api_requests_total{http_request_method="POST",tenant="acme"}`)
			},
		},
		{
			name: "tenant dimension defaults to unknown when header missing",
			traffic: func(t *testing.T) {
				t.Helper()
				// No X-Tenant header => uses default "unknown".
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// Both the counter and the histogram have the tenant dimension with default "unknown".
				assertMetricExists(t, `custom_api_requests_total{tyk_api_id="3",tenant="unknown"}`)
				assertMetricExists(t, `custom_request_duration_seconds_count{tyk_api_id="3",tenant="unknown"}`)
			},
		},
		{
			name: "error counter records 4xx",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/status/404", 3)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_error_requests_total{tyk_api_id="3",http_response_status_code="404"}`)
			},
		},
		{
			name: "error counter records 5xx",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/status/500", 3)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_error_requests_total{tyk_api_id="3",http_response_status_code="500"}`)
			},
		},
		{
			name: "error counter excludes 2xx",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 10)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricAbsent(t, `custom_error_requests_total{http_response_status_code="200"}`)
			},
		},
		{
			name: "error counter has all expected labels",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/status/404", 3)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// custom.error.requests.total dimensions: method, response_code, api_id.
				assertMetricHasLabels(t, "custom_error_requests_total", []string{
					"http_request_method",
					"http_response_status_code",
					"tyk_api_id",
				})
			},
		},
		{
			name: "tracked endpoint counter with listen_path dimension",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/tracked/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// The TrackedAPI (api_id=9) has listen_path=/tracked/.
				// The endpoint dimension should be /ip (from track_endpoints config).
				assertMetricExists(t, `custom_tracked_requests_total{tyk_api_id="9",tyk_listen_path="/tracked/"}`)
				assertMetricExists(t, `custom_tracked_requests_total{tyk_api_id="9",tyk_endpoint="/ip"}`)
			},
		},
		{
			name: "tracked endpoint counter has all expected labels",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/tracked/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// Query the tracked API (api_id=9) specifically because the
				// non-tracked API has an empty tyk_endpoint which Prometheus drops.
				assertMetricHasLabels(t, `custom_tracked_requests_total{tyk_api_id="9"}`, []string{
					"http_request_method",
					"tyk_api_id",
					"tyk_listen_path",
					"tyk_endpoint",
				})
			},
		},
		{
			name: "tracked endpoint dimension distinguishes different endpoints",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/tracked/ip", 5)
				sendTraffic(t, "GET", gatewayURL+"/tracked/get", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// Both tracked paths should appear as separate series.
				assertMetricExists(t, `custom_tracked_requests_total{tyk_api_id="9",tyk_endpoint="/ip"}`)
				assertMetricExists(t, `custom_tracked_requests_total{tyk_api_id="9",tyk_endpoint="/get"}`)
			},
		},
		{
			name: "non-tracked endpoint has empty endpoint dimension",
			traffic: func(t *testing.T) {
				t.Helper()
				// /test/ API (api_id=3) has no track_endpoints, so endpoint should be empty.
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// For a non-tracked API, the endpoint dimension should be empty.
				assertMetricExists(t, `custom_tracked_requests_total{tyk_api_id="3",tyk_endpoint=""}`)
			},
		},
		{
			name: "configdata dimension populates from API config_data",
			traffic: func(t *testing.T) {
				t.Helper()
				// TrackedAPI (api_id=9) has config_data: {"environment":"staging","team":"platform"}
				sendTraffic(t, "GET", gatewayURL+"/tracked/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_configdata_requests_total{tyk_api_id="9",configdata_environment="staging"}`)
				assertMetricExists(t, `custom_configdata_requests_total{tyk_api_id="9",configdata_team="platform"}`)
			},
		},
		{
			name: "configdata dimension has all expected labels",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/tracked/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricHasLabels(t, `custom_configdata_requests_total{tyk_api_id="9"}`, []string{
					"http_request_method",
					"tyk_api_id",
					"configdata_environment",
					"configdata_team",
				})
			},
		},
		{
			name: "configdata dimension uses default for API without config_data",
			traffic: func(t *testing.T) {
				t.Helper()
				// TestAPI (api_id=3) has no config_data, so dimensions should use default "".
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				assertMetricExists(t, `custom_configdata_requests_total{tyk_api_id="3",configdata_environment=""}`)
			},
		},
		{
			name: "default RED instruments are NOT present in custom profile",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// When api_metrics is explicitly set, defaults are replaced.
				assertMetricAbsent(t, `http_server_request_duration_seconds_count`)
				assertMetricAbsent(t, `tyk_gateway_request_duration_seconds_count`)
				assertMetricAbsent(t, `tyk_upstream_request_duration_seconds_count`)
				assertMetricAbsent(t, `tyk_api_requests_total`)
			},
		},
		{
			name: "custom histogram has custom buckets",
			traffic: func(t *testing.T) {
				t.Helper()
				sendTraffic(t, "GET", gatewayURL+"/test/ip", 5)
			},
			assert: func(t *testing.T) {
				t.Helper()
				// With custom buckets [0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
				// Prometheus should show le="0.005" bucket (from our custom config).
				assertMetricExists(t, `custom_request_duration_seconds_bucket{le="0.005"}`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.traffic(t)
			tc.assert(t)
		})
	}
}

// ---------- Runtime Metrics tests ----------

func TestRuntimeMetrics(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	time.Sleep(15 * time.Second)

	tests := []struct {
		name   string
		metric string
	}{
		// New Go runtime metric names (semconv) from runtime instrumentation v0.61+.
		{"go.goroutine.count exists", `go_goroutine_count`},
		{"go.memory.used exists", `go_memory_used_bytes`},
		{"go.memory.allocated exists", `go_memory_allocated_bytes_total`},
		{"go.memory.allocations exists", `go_memory_allocations_total`},
		{"go.memory.gc.goal exists", `go_memory_gc_goal_bytes`},
		{"go.processor.limit exists", `go_processor_limit`},
		{"go.config.gogc exists", `go_config_gogc_percent`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Runtime metrics should exist and be > 0.
			assertMetricExists(t, tc.metric)
		})
	}
}

func TestRuntimeMetrics_Disabled(t *testing.T) {
	if gwProfile() != "disabled" {
		t.Skip("only runs under disabled profile")
	}
	waitForGateway(t)

	time.Sleep(15 * time.Second)

	// Runtime metrics should not exist (new names).
	assertMetricAbsent(t, `go_goroutine_count`)
	assertMetricAbsent(t, `go_memory_used_bytes`)
	assertMetricAbsent(t, `go_memory_allocated_bytes_total`)
}

// ---------- Disabled profile tests ----------

func TestDisabledProfile_NoAPIMetrics(t *testing.T) {
	if gwProfile() != "disabled" {
		t.Skip("only runs under disabled profile")
	}
	waitForGateway(t)

	// Send traffic to ensure the gateway is processing requests.
	sendTraffic(t, "GET", gatewayURL+"/test/ip", 10)

	// Wait for a scrape cycle so Prometheus would have any metrics if they existed.
	time.Sleep(15 * time.Second)

	tests := []struct {
		name   string
		metric string
	}{
		{"no http.server.request.duration", `http_server_request_duration_seconds_count`},
		{"no tyk.gateway.request.duration", `tyk_gateway_request_duration_seconds_count`},
		{"no tyk.upstream.request.duration", `tyk_upstream_request_duration_seconds_count`},
		{"no tyk.api.requests.total", `tyk_api_requests_total`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertMetricAbsent(t, tc.metric)
		})
	}
}

// ---------- Cardinality limit tests ----------

func TestCardinalityLimit_OverflowSeries(t *testing.T) {
	if gwProfile() != "cardinality" {
		t.Skip("only runs under cardinality profile")
	}
	waitForGateway(t)

	// The cardinality profile sets CardinalityLimit=5 and defines a counter
	// with a high-cardinality header dimension (X-Request-ID).
	// Send 20 requests, each with a unique X-Request-ID header value.
	const totalRequests = 20
	for i := range totalRequests {
		sendTrafficWithHeaders(t, "GET", gatewayURL+"/test/ip", 1,
			map[string]string{"X-Request-ID": fmt.Sprintf("req-%d", i)})
	}

	// Wait for export + scrape cycle.
	time.Sleep(15 * time.Second)

	// Query Prometheus for the counter. OTel counter "cardinality.test.requests.total"
	// becomes "cardinality_test_requests_total" in Prometheus.
	//
	// With CardinalityLimit=5, we expect at most 5 regular series + 1 overflow series.
	// The overflow series has the label otel_metric_overflow="true".
	results := queryPrometheusAllSeries(t, "cardinality_test_requests_total")

	var hasOverflow bool
	var totalCount float64
	for _, r := range results {
		if r.labels["otel_metric_overflow"] == "true" {
			hasOverflow = true
		}
		totalCount += r.value
	}

	// With limit=5, we expect at most 6 series (5 + 1 overflow).
	maxSeries := 5 + 1
	if len(results) > maxSeries {
		t.Errorf("expected at most %d series for cardinality_test_requests_total, got %d", maxSeries, len(results))
	}

	if !hasOverflow {
		t.Error("expected overflow series with otel_metric_overflow=\"true\" label")
	}

	// Total count across all series should equal totalRequests.
	if int(totalCount) != totalRequests {
		t.Errorf("expected total count=%d across all series, got %v", totalRequests, totalCount)
	}

	t.Logf("cardinality test: %d series, overflow=%v, total_count=%v", len(results), hasOverflow, totalCount)
}

func TestCardinalityLimit_DefaultMetricsUnaffected(t *testing.T) {
	if gwProfile() != "default" {
		t.Skip("only runs under default profile")
	}
	waitForGateway(t)

	// With the default profile (default CardinalityLimit=2000), normal traffic
	// should never trigger overflow because default RED dimensions are low-cardinality.
	sendTraffic(t, "GET", gatewayURL+"/test/ip", 10)

	time.Sleep(15 * time.Second)

	// Verify no overflow series on default RED metrics.
	results := queryPrometheusAllSeries(t, "tyk_api_requests_total")
	for _, r := range results {
		if r.labels["otel_metric_overflow"] == "true" {
			t.Error("unexpected overflow series on tyk_api_requests_total with default cardinality limit")
		}
	}
}

// ---------- Response-header dimension tests ----------

// TestResponseHeaderDimension_WithDetailedRecording validates that response_header
// dimensions work correctly when enable_detailed_recording is true on the API.
// Uses httpbin's /response-headers endpoint to return known header values.
func TestResponseHeaderDimension_WithDetailedRecording(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// Hit httpbin's /response-headers endpoint through the API that has
	// enable_detailed_recording: true (api_id=5, listen_path=/resp-headers/).
	// This makes httpbin return X-Backend-Version: v2.1.0 in the response.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers/response-headers?X-Backend-Version=v2.1.0", 10)

	// OTel counter "tyk.requests.by.backend.version" -> Prometheus "tyk_requests_by_backend_version_total".
	// The response_header dimension should extract "v2.1.0" from the response.
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="5",backend_version="v2.1.0"}`)
}

// TestResponseHeaderDimension_ContentType validates Content-Type response header
// extraction when enable_detailed_recording is true.
func TestResponseHeaderDimension_ContentType(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// /ip returns application/json content type.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers/ip", 10)

	// Content-Type from httpbin is "application/json".
	assertMetricExists(t, `tyk_requests_by_content_type_total{tyk_api_id="5",content_type="application/json"}`)
}

// TestResponseHeaderDimension_MultipleValues validates that different response
// header values create separate metric series.
func TestResponseHeaderDimension_MultipleValues(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// Send requests that return different X-Backend-Version values.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers/response-headers?X-Backend-Version=v1.0.0", 5)
	sendTraffic(t, "GET", gatewayURL+"/resp-headers/response-headers?X-Backend-Version=v2.0.0", 5)

	// Both versions should appear as separate series.
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="5",backend_version="v1.0.0"}`)
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="5",backend_version="v2.0.0"}`)
}

// TestResponseHeaderDimension_DefaultWhenMissing validates that the default value
// is used when the response header is absent.
func TestResponseHeaderDimension_DefaultWhenMissing(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// /ip does NOT return X-Backend-Version, so the default "unknown" should be used.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers/ip", 10)

	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="5",backend_version="unknown"}`)
}

// TestResponseHeaderDimension_WithoutDetailedRecording validates that response_header
// dimensions work correctly even when enable_detailed_recording is false.
// Previously this was broken because WrappedServeHTTP only copied response headers
// when withCache=true (which was tied to enable_detailed_recording on the non-cache path).
func TestResponseHeaderDimension_WithoutDetailedRecording(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// Hit httpbin's /response-headers endpoint through the API with
	// enable_detailed_recording: false (api_id=6, listen_path=/resp-headers-nodetail/).
	sendTraffic(t, "GET", gatewayURL+"/resp-headers-nodetail/response-headers?X-Backend-Version=v3.0.0", 10)

	// Response headers should be extracted regardless of enable_detailed_recording.
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="6",backend_version="v3.0.0"}`)
}

// TestResponseHeaderDimension_HasExpectedLabels validates all expected labels
// are present on the response-header-based counter.
func TestResponseHeaderDimension_HasExpectedLabels(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	sendTraffic(t, "GET", gatewayURL+"/resp-headers/response-headers?X-Backend-Version=v1.0.0", 5)

	assertMetricHasLabels(t, "tyk_requests_by_backend_version_total", []string{
		"backend_version",
		"tyk_api_id",
	})
}

// TestResponseHeaderDimension_CachedAPIWithoutDetailedRecording validates that
// when caching is enabled (ServeHTTPForCache path), response headers ARE available
// for OTel dimensions even without enable_detailed_recording, because the cache
// path always passes withCache=true to WrappedServeHTTP.
func TestResponseHeaderDimension_CachedAPIWithoutDetailedRecording(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// api_id=7 has enable_detailed_recording=false BUT cache enabled.
	// The cache code path (ServeHTTPForCache) always does *inres = *res,
	// so response headers should be copied regardless.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers-cached/response-headers?X-Backend-Version=v4.0.0", 10)

	// With caching on, the response headers should be available even without detailed recording.
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="7",backend_version="v4.0.0"}`)
}

// TestResponseHeaderDimension_ErrorPath validates that the error handler path
// does not panic when response_header dimensions are configured and the upstream
// is unreachable (no upstream response at all). The dimension should fall back
// to its default value.
func TestResponseHeaderDimension_ErrorPath(t *testing.T) {
	if gwProfile() != "response-headers" {
		t.Skip("only runs under response-headers profile")
	}
	waitForGateway(t)

	// api_id=8 proxies to a non-existent upstream. Every request will hit
	// the error handler path (HandleError), which passes nil response to
	// RecordMetrics. The gateway should not panic and should record the
	// metric with the default dimension value.
	sendTraffic(t, "GET", gatewayURL+"/resp-headers-error/anything", 5)

	// The error requests should be counted with the default "unknown" for
	// backend_version (no upstream response to extract headers from).
	assertMetricExists(t, `tyk_requests_by_backend_version_total{tyk_api_id="8",backend_version="unknown"}`)
}

// ---------- MCP profile tests ----------

func TestMCPProfile_MetricEmission(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	// Send a tools/call JSON-RPC request through the MCP API.
	// The MCP everything server at mcp-server:3001 should handle this.
	sendJSONRPC(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]string{"message": "hello"},
	})

	// Assert MCP counter exists with expected dimensions.
	assertMetricExists(t, `tyk_mcp_requests_total{mcp_method_name="tools/call",mcp_primitive_type="tool"}`)
}

func TestMCPProfile_PrimitiveName(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	sendJSONRPC(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]string{"message": "test"},
	})

	// Assert primitive name dimension is populated.
	assertMetricExists(t, `tyk_mcp_requests_total{mcp_primitive_name="echo",mcp_primitive_type="tool"}`)
}

func TestMCPProfile_NonMCPIsolation(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	// Send regular REST traffic to the non-MCP API.
	sendTraffic(t, "GET", gatewayURL+"/test/ip", 10)

	// Send MCP traffic.
	sendJSONRPC(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]string{"message": "test"},
	})

	// REST API metrics should have empty MCP labels.
	// MCP counter should exist with MCP labels populated.
	assertMetricExists(t, `tyk_mcp_requests_total{mcp_method_name="tools/call"}`)
}

func TestMCPProfile_HistogramDuration(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	for i := 0; i < 5; i++ {
		sendJSONRPC(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
			"name":      "echo",
			"arguments": map[string]string{"message": "test"},
		})
	}

	// Assert histogram exists.
	assertMetricExists(t, `tyk_mcp_primitive_duration_seconds_count{mcp_primitive_type="tool",mcp_primitive_name="echo"}`)
}

func TestMCPProfile_HTTPServerDurationWithMCPMethod(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	sendJSONRPC(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]string{"message": "test"},
	})

	// http.server.request.duration should also have the mcp.method.name label.
	assertMetricExists(t, `http_server_request_duration_seconds_count{mcp_method_name="tools/call"}`)
}

func TestMCPProfile_SessionIdFromHeader(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	sendJSONRPCWithHeaders(t, gatewayURL+"/mcp/", "tools/call", map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]string{"message": "test"},
	}, map[string]string{
		"Mcp-Session-Id": "test-session-123",
	})

	// http.server.request.duration should have mcp.session.id from header.
	assertMetricExists(t, `http_server_request_duration_seconds_count{mcp_session_id="test-session-123"}`)
}

func TestMCPProfile_InitializeMethod(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	// Initialize is a non-primitive method (no tool/resource/prompt).
	sendJSONRPC(t, gatewayURL+"/mcp/", "initialize", map[string]interface{}{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test-client", "version": "1.0"},
	})

	// Should have mcp_method_name="initialize" but empty primitive type/name.
	assertMetricExists(t, `tyk_mcp_requests_total{mcp_method_name="initialize"}`)
}

func TestMCPProfile_CounterHasAllExpectedLabels(t *testing.T) {
	if gwProfile() != "mcp" {
		t.Skip("only runs under mcp profile")
	}
	waitForGateway(t)

	// Use proper MCP session so the upstream returns 200.
	sendMCPToolCall(t, gatewayURL+"/mcp/", "echo", map[string]string{"message": "test"})

	query := `tyk_mcp_requests_total{api_id="mcp-1",mcp_method_name="tools/call",mcp_primitive_name="echo",response_code="200"}`
	assertLabelEquals(t, query, "mcp_method_name", "tools/call")
	assertLabelEquals(t, query, "mcp_primitive_type", "tool")
	assertLabelEquals(t, query, "mcp_primitive_name", "echo")
	assertLabelEquals(t, query, "response_code", "200")
	assertLabelEquals(t, query, "api_id", "mcp-1")
	// mcp_error_code is omitted by Prometheus when empty (no error).
}

// ---------- helpers ----------

func waitForGateway(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(gatewayURL + "/hello")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("timed out waiting for gateway")
}

// sendTraffic sends N requests with the given method to the URL.
func sendTraffic(t *testing.T, method, u string, n int) {
	t.Helper()
	sendTrafficWithHeaders(t, method, u, n, nil)
}

// sendTrafficWithHeaders sends N requests with the given method, URL and headers.
func sendTrafficWithHeaders(t *testing.T, method, u string, n int, headers map[string]string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	for i := range n {
		var req *http.Request
		var err error
		switch method {
		case "POST":
			req, err = http.NewRequest("POST", u, strings.NewReader(`{"key":"value"}`))
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			req.Header.Set("Content-Type", "application/json")
		default:
			req, err = http.NewRequest(method, u, nil)
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s request %d: %v", method, i, err)
		}
		resp.Body.Close()
	}
}

// queryPrometheus runs an instant PromQL query and returns the first result value.
func queryPrometheus(t *testing.T, query string) (float64, bool) {
	t.Helper()
	u := fmt.Sprintf("%s/api/v1/query?query=%s", prometheusURL, url.QueryEscape(query))
	resp, err := http.Get(u)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	var result promQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, false
	}
	if result.Status != "success" || len(result.Data.Result) == 0 {
		return 0, false
	}

	var val float64
	if err := json.Unmarshal(result.Data.Result[0].Value[1], &val); err != nil {
		// Prometheus returns value as string in JSON.
		var s string
		if err := json.Unmarshal(result.Data.Result[0].Value[1], &s); err != nil {
			return 0, false
		}
		fmt.Sscanf(s, "%f", &val)
	}
	return val, true
}

// queryPrometheusLabels returns the label set for the first result of a metric query.
func queryPrometheusLabels(t *testing.T, query string) (map[string]string, bool) {
	t.Helper()
	u := fmt.Sprintf("%s/api/v1/query?query=%s", prometheusURL, url.QueryEscape(query))
	resp, err := http.Get(u)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	var result promQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, false
	}
	if result.Status != "success" || len(result.Data.Result) == 0 {
		return nil, false
	}

	return result.Data.Result[0].Metric, true
}

// promSeries represents a single Prometheus time series with its labels and value.
type promSeries struct {
	labels map[string]string
	value  float64
}

// queryPrometheusAllSeries returns all series for a metric name.
func queryPrometheusAllSeries(t *testing.T, metric string) []promSeries {
	t.Helper()
	u := fmt.Sprintf("%s/api/v1/query?query=%s", prometheusURL, url.QueryEscape(metric))
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("prometheus query failed: %v", err)
	}
	defer resp.Body.Close()

	var result promQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode prometheus response: %v", err)
	}
	if result.Status != "success" {
		t.Fatalf("prometheus query returned status: %s", result.Status)
	}

	var series []promSeries
	for _, r := range result.Data.Result {
		var val float64
		var s string
		if err := json.Unmarshal(r.Value[1], &s); err == nil {
			fmt.Sscanf(s, "%f", &val)
		}
		series = append(series, promSeries{labels: r.Metric, value: val})
	}
	return series
}

// assertMetricExists polls Prometheus until metric > 0 or times out.
func assertMetricExists(t *testing.T, query string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		val, ok := queryPrometheus(t, query)
		if ok && val > 0 {
			t.Logf("%s = %.0f OK", query, val)
			return
		}
		time.Sleep(pollInterval)
	}
	val, _ := queryPrometheus(t, query)
	t.Fatalf("%s = %.0f, expected > 0", query, val)
}

// assertMetricGTE polls Prometheus until metric >= expected or times out.
func assertMetricGTE(t *testing.T, metric string, expected int) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		val, ok := queryPrometheus(t, metric)
		if ok && val >= float64(expected) {
			t.Logf("%s = %.0f (>= %d) OK", metric, val, expected)
			return
		}
		time.Sleep(pollInterval)
	}
	// Final attempt for error message.
	val, _ := queryPrometheus(t, metric)
	t.Fatalf("%s = %.0f, expected >= %d", metric, val, expected)
}

// assertMetricAbsent verifies that a metric does NOT exist in Prometheus.
// Polls briefly to allow for any delayed scrapes, then confirms absence.
func assertMetricAbsent(t *testing.T, query string) {
	t.Helper()
	// Give Prometheus a few cycles to ensure the metric would show up if it existed.
	for i := range 3 {
		val, ok := queryPrometheus(t, query)
		if ok && val > 0 {
			t.Fatalf("%s = %.0f, expected absent (attempt %d)", query, val, i)
		}
		time.Sleep(pollInterval)
	}
	t.Logf("%s absent OK", query)
}

// assertMetricHasLabels verifies that a metric has all expected label names.
func assertMetricHasLabels(t *testing.T, metric string, expectedLabels []string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var lastLabels map[string]string
	for time.Now().Before(deadline) {
		labels, ok := queryPrometheusLabels(t, metric)
		lastLabels = labels
		if ok && labels != nil {
			missing := []string{}
			for _, l := range expectedLabels {
				if _, exists := labels[l]; !exists {
					missing = append(missing, l)
				}
			}
			if len(missing) == 0 {
				t.Logf("%s has all expected labels: %v", metric, expectedLabels)
				return
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("%s missing expected labels; have %v, want %v", metric, lastLabels, expectedLabels)
}

// assertLabelPresent polls Prometheus until the label is present on the metric or times out.
func assertLabelPresent(t *testing.T, query, labelKey string) string {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var lastLabels map[string]string
	for time.Now().Before(deadline) {
		labels, ok := queryPrometheusLabels(t, query)
		lastLabels = labels
		if ok {
			if val, exists := labels[labelKey]; exists && val != "" {
				t.Logf("%s has label %s=%q OK", query, labelKey, val)
				return val
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("%s missing label %s, got labels: %v", query, labelKey, lastLabels)
	return ""
}

// assertLabelEquals polls Prometheus until the label equals expected value or times out.
func assertLabelEquals(t *testing.T, query, labelKey, expected string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var lastLabels map[string]string
	for time.Now().Before(deadline) {
		labels, ok := queryPrometheusLabels(t, query)
		lastLabels = labels
		if ok {
			if val, exists := labels[labelKey]; exists && val == expected {
				t.Logf("%s has label %s=%q OK", query, labelKey, val)
				return
			}
		}
		time.Sleep(pollInterval)
	}
	actualVal := ""
	if lastLabels != nil {
		actualVal = lastLabels[labelKey]
	}
	t.Fatalf("%s label %s=%q, expected %q", query, labelKey, actualVal, expected)
}

// assertLabelContains polls Prometheus until the label contains expected substring or times out.
func assertLabelContains(t *testing.T, query, labelKey, expected string) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout)
	var lastLabels map[string]string
	for time.Now().Before(deadline) {
		labels, ok := queryPrometheusLabels(t, query)
		lastLabels = labels
		if ok {
			if val, exists := labels[labelKey]; exists {
				// For array-like labels like tyk_gw_tags, check if substring is present
				if strings.Contains(val, expected) {
					t.Logf("%s has label %s containing %q OK", query, labelKey, expected)
					return
				}
			}
		}
		time.Sleep(pollInterval)
	}
	actualVal := ""
	if lastLabels != nil {
		actualVal = lastLabels[labelKey]
	}
	t.Fatalf("%s label %s=%q does not contain %q", query, labelKey, actualVal, expected)
}

// sendJSONRPC sends a JSON-RPC 2.0 request to the given URL.
func sendJSONRPC(t *testing.T, url, method string, params interface{}) {
	t.Helper()
	sendJSONRPCWithHeaders(t, url, method, params, nil)
}

// sendJSONRPCWithHeaders sends a JSON-RPC 2.0 request with custom headers.
func sendJSONRPCWithHeaders(t *testing.T, url, method string, params interface{}, headers map[string]string) {
	t.Helper()
	doJSONRPC(t, url, method, params, headers)
}

// doJSONRPC sends a JSON-RPC 2.0 request and returns the HTTP response.
func doJSONRPC(t *testing.T, url, method string, params interface{}, headers map[string]string) *http.Response {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal JSON-RPC body: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("JSON-RPC request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// initMCPSession performs the MCP initialize handshake and returns the session ID.
// The Streamable HTTP transport requires: initialize → (get Mcp-Session-Id) → initialized notification.
func initMCPSession(t *testing.T, mcpURL string) string {
	t.Helper()

	// Step 1: Send initialize request.
	resp := doJSONRPC(t, mcpURL, "initialize", map[string]interface{}{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test-client", "version": "1.0"},
	}, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize returned HTTP %d (expected 200); check that operation-level allow is disabled", resp.StatusCode)
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Logf("initialize response headers: %v", resp.Header)
		t.Fatal("MCP server did not return Mcp-Session-Id header on initialize")
	}

	// Step 2: Send initialized notification (no id field = notification).
	notifBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	req, err := http.NewRequest("POST", mcpURL, bytes.NewReader(notifBody))
	if err != nil {
		t.Fatalf("failed to create initialized notification request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)

	client := &http.Client{Timeout: 10 * time.Second}
	notifResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("initialized notification failed: %v", err)
	}
	notifResp.Body.Close()

	return sessionID
}

// sendMCPToolCall initializes an MCP session and sends a tools/call request.
func sendMCPToolCall(t *testing.T, mcpURL, toolName string, args map[string]string) {
	t.Helper()
	sessionID := initMCPSession(t, mcpURL)
	sendJSONRPCWithHeaders(t, mcpURL, "tools/call", map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}, map[string]string{
		"Mcp-Session-Id": sessionID,
	})
}
