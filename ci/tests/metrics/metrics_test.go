package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
			Value [2]json.RawMessage `json:"value"`
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

func TestRequestCounter(t *testing.T) {
	waitForGateway(t)

	// Send requests.
	const N = 20
	for i := range N {
		resp, err := http.Get(gatewayURL + "/test/ip")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	// Poll Prometheus until counter >= N or timeout.
	// OTel counter names get a "_total" suffix in Prometheus.
	assertMetricGTE(t, "tyk_http_requests_total", N)
}

// --- helpers ---

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
