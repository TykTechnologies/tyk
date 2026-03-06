package main

import (
	"encoding/json"
	"fmt"
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
	for time.Now().Before(deadline) {
		labels, ok := queryPrometheusLabels(t, metric)
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
	labels, _ := queryPrometheusLabels(t, metric)
	t.Fatalf("%s missing expected labels; have %v, want %v", metric, labels, expectedLabels)
}
