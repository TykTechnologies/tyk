package apimetrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	tykmetric "github.com/TykTechnologies/opentelemetry/metric"
	"github.com/TykTechnologies/opentelemetry/metric/metrictest"

	"github.com/TykTechnologies/tyk/user"
)

// makeRealRegistry creates an InstrumentRegistry backed by a real OTel provider
// with ManualReader. The returned TestProvider allows asserting recorded metric
// values and attributes.
func makeRealRegistry(t *testing.T, defs []APIMetricDefinition) (*InstrumentRegistry, *metrictest.TestProvider) {
	t.Helper()
	tp := metrictest.NewProvider(t)
	reg, err := NewInstrumentRegistry(tp, defs)
	require.NoError(t, err)
	return reg, tp
}

// metricAssertion describes the expected state of a single metric after recording.
type metricAssertion struct {
	Name       string            // metric name
	Type       string            // "counter" or "histogram"
	Sum        int64             // for counter: expected sum across all data points
	HistCount  uint64            // for histogram: expected total observation count
	HistSum    float64           // for histogram: expected sum of all recorded values
	Attrs      map[string]string // expected attribute subset (all apimetrics dimensions are strings)
	NotPresent bool              // if true, metric should NOT appear in collected data
}

// toKeyValues converts a string map to OTel attribute.KeyValue slice.
func toKeyValues(m map[string]string) []attribute.KeyValue {
	kvs := make([]attribute.KeyValue, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, attribute.String(k, v))
	}
	return kvs
}

// assertMetrics validates all metric assertions against the collected data.
func assertMetrics(t *testing.T, tp *metrictest.TestProvider, asserts []metricAssertion) {
	t.Helper()
	for _, a := range asserts {
		if a.NotPresent {
			names := tp.MetricNames()
			assert.NotContains(t, names, a.Name, "metric %q should not be recorded", a.Name)
			continue
		}

		m := tp.FindMetric(t, a.Name)
		switch a.Type {
		case "counter":
			metrictest.AssertSum(t, m, a.Sum)
		case "histogram":
			metrictest.AssertHistogramCount(t, m, a.HistCount)
			metrictest.AssertHistogramSum(t, m, a.HistSum)
		}
		if len(a.Attrs) > 0 {
			metrictest.AssertHasAttributes(t, m, toKeyValues(a.Attrs)...)
		}
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Counter scenarios
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_Counters(t *testing.T) {
	tests := []struct {
		name    string
		defs    []APIMetricDefinition
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "single counter increment",
			defs: []APIMetricDefinition{
				{Name: "test.counter", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "test.counter", Type: "counter", Sum: 1, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "counter accumulates across multiple recordings",
			defs: []APIMetricDefinition{
				{Name: "acc.counter", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "acc.counter", Type: "counter", Sum: 3, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "counter with multiple metadata dimensions",
			defs: []APIMetricDefinition{
				{Name: "multi.dim", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "http.method"},
					{Source: "metadata", Key: "api_id", Label: "api"},
					{Source: "metadata", Key: "response_code", Label: "status"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 201, APIID: "my-api"},
			},
			asserts: []metricAssertion{
				{Name: "multi.dim", Type: "counter", Sum: 1, Attrs: map[string]string{
					"http.method": "POST",
					"api":         "my-api",
					"status":      "201",
				}},
			},
		},
		{
			name: "counter splits data points by different attribute values",
			defs: []APIMetricDefinition{
				{Name: "split.counter", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				// Total across all data points: GET(2) + POST(1) = 3.
				{Name: "split.counter", Type: "counter", Sum: 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, tt.defs)
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Histogram scenarios
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_Histograms(t *testing.T) {
	tests := []struct {
		name    string
		defs    []APIMetricDefinition
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "histogram total latency (ms to seconds)",
			defs: []APIMetricDefinition{
				{Name: "h.total", Type: "histogram", HistogramSource: "total", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 150, LatencyGateway: 50, LatencyUpstream: 100},
			},
			asserts: []metricAssertion{
				{Name: "h.total", Type: "histogram", HistCount: 1, HistSum: 0.15, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "histogram gateway latency",
			defs: []APIMetricDefinition{
				{Name: "h.gw", Type: "histogram", HistogramSource: "gateway", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 150, LatencyGateway: 50, LatencyUpstream: 100},
			},
			asserts: []metricAssertion{
				{Name: "h.gw", Type: "histogram", HistCount: 1, HistSum: 0.05, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "histogram upstream latency",
			defs: []APIMetricDefinition{
				{Name: "h.up", Type: "histogram", HistogramSource: "upstream", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 150, LatencyGateway: 50, LatencyUpstream: 100},
			},
			asserts: []metricAssertion{
				{Name: "h.up", Type: "histogram", HistCount: 1, HistSum: 0.1, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "histogram accumulates multiple observations",
			defs: []APIMetricDefinition{
				{Name: "h.acc", Type: "histogram", HistogramSource: "total", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 500},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 250},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 1000},
			},
			asserts: []metricAssertion{
				// 3 observations: 0.5 + 0.25 + 1.0 = 1.75s (exact binary fractions).
				{Name: "h.acc", Type: "histogram", HistCount: 3, HistSum: 1.75},
			},
		},
		{
			name: "histogram with custom buckets",
			defs: []APIMetricDefinition{
				{Name: "h.custom", Type: "histogram", HistogramSource: "total",
					HistogramBuckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0},
					Dimensions: []DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "method"},
					}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1", LatencyTotal: 50},
			},
			asserts: []metricAssertion{
				{Name: "h.custom", Type: "histogram", HistCount: 1, HistSum: 0.05},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, tt.defs)
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Dimension source scenarios
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_DimensionSources(t *testing.T) {
	tests := []struct {
		name    string
		defs    []APIMetricDefinition
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "header dimension extracts value",
			defs: []APIMetricDefinition{
				{Name: "hdr.c", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "header", Key: "X-Customer-ID", Label: "customer_id", Default: "unknown"},
				}},
			},
			inputs: []*RequestContext{
				func() *RequestContext {
					r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
					r.Header.Set("X-Customer-ID", "cust-42")
					return &RequestContext{Request: r, StatusCode: 200, APIID: "api-1"}
				}(),
			},
			asserts: []metricAssertion{
				{Name: "hdr.c", Type: "counter", Sum: 1, Attrs: map[string]string{"customer_id": "cust-42"}},
			},
		},
		{
			name: "header dimension uses default when missing",
			defs: []APIMetricDefinition{
				{Name: "hdr.default", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "header", Key: "X-Missing", Label: "missing_hdr", Default: "fallback"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "hdr.default", Type: "counter", Sum: 1, Attrs: map[string]string{"missing_hdr": "fallback"}},
			},
		},
		{
			name: "session dimensions (oauth_id and truncated api_key)",
			defs: []APIMetricDefinition{
				{Name: "sess.c", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "session", Key: "oauth_id", Label: "oauth"},
					{Source: "session", Key: "api_key", Label: "key"},
				}},
			},
			inputs: []*RequestContext{
				{
					Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1",
					Token: "abcdefghij", Session: &user.SessionState{OauthClientID: "oauth-client-1"},
				},
			},
			asserts: []metricAssertion{
				{Name: "sess.c", Type: "counter", Sum: 1, Attrs: map[string]string{
					"oauth": "oauth-client-1",
					"key":   "efghij", // truncateKey: last 6 chars
				}},
			},
		},
		{
			name: "context dimension extracts variable",
			defs: []APIMetricDefinition{
				{Name: "ctx.c", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "context", Key: "tier", Label: "tier", Default: "basic"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1",
					ContextVariables: map[string]any{"tier": "premium"}},
			},
			asserts: []metricAssertion{
				{Name: "ctx.c", Type: "counter", Sum: 1, Attrs: map[string]string{"tier": "premium"}},
			},
		},
		{
			name: "context dimension uses default when missing",
			defs: []APIMetricDefinition{
				{Name: "ctx.def", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "context", Key: "tier", Label: "tier", Default: "basic"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "ctx.def", Type: "counter", Sum: 1, Attrs: map[string]string{"tier": "basic"}},
			},
		},
		{
			name: "response_header dimension extracts value",
			defs: []APIMetricDefinition{
				{Name: "resp.c", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "response_header", Key: "X-Cache-Status", Label: "cache", Default: "MISS"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1",
					Response: &http.Response{Header: http.Header{"X-Cache-Status": []string{"HIT"}}}},
			},
			asserts: []metricAssertion{
				{Name: "resp.c", Type: "counter", Sum: 1, Attrs: map[string]string{"cache": "HIT"}},
			},
		},
		{
			name: "response_header dimension uses default when response is nil",
			defs: []APIMetricDefinition{
				{Name: "resp.def", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "response_header", Key: "X-Cache-Status", Label: "cache", Default: "MISS"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 500, APIID: "api-1", Response: nil},
			},
			asserts: []metricAssertion{
				{Name: "resp.def", Type: "counter", Sum: 1, Attrs: map[string]string{"cache": "MISS"}},
			},
		},
		{
			name: "mixed dimension sources on single instrument",
			defs: []APIMetricDefinition{
				{Name: "mixed.c", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
					{Source: "header", Key: "X-Tenant", Label: "tenant", Default: "default"},
					{Source: "context", Key: "env", Label: "env", Default: "prod"},
				}},
			},
			inputs: []*RequestContext{
				func() *RequestContext {
					r := httptest.NewRequest(http.MethodPut, "http://example.com/", nil)
					r.Header.Set("X-Tenant", "acme")
					return &RequestContext{Request: r, StatusCode: 200, APIID: "api-1",
						ContextVariables: map[string]any{"env": "staging"}}
				}(),
			},
			asserts: []metricAssertion{
				{Name: "mixed.c", Type: "counter", Sum: 1, Attrs: map[string]string{
					"method": "PUT",
					"tenant": "acme",
					"env":    "staging",
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, tt.defs)
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Filter scenarios
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_Filters(t *testing.T) {
	tests := []struct {
		name    string
		defs    []APIMetricDefinition
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "api_id filter skips non-matching request",
			defs: []APIMetricDefinition{
				{Name: "f.api", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}, Filters: &MetricFilters{APIIDs: []string{"api-only"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "different-api"},
			},
			asserts: []metricAssertion{
				{Name: "f.api", NotPresent: true},
			},
		},
		{
			name: "api_id filter passes matching request",
			defs: []APIMetricDefinition{
				{Name: "f.api.match", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}, Filters: &MetricFilters{APIIDs: []string{"api-only"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-only"},
			},
			asserts: []metricAssertion{
				{Name: "f.api.match", Type: "counter", Sum: 1, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "method filter passes GET but skips POST",
			defs: []APIMetricDefinition{
				{Name: "f.method", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}, Filters: &MetricFilters{Methods: []string{"GET"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "f.method", Type: "counter", Sum: 1, Attrs: map[string]string{"method": "GET"}},
			},
		},
		{
			name: "status code filter 4xx/5xx passes 500 but skips 200",
			defs: []APIMetricDefinition{
				{Name: "f.status", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "response_code", Label: "status"},
				}, Filters: &MetricFilters{StatusCodes: []string{"4xx", "5xx"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 500, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				{Name: "f.status", Type: "counter", Sum: 1, Attrs: map[string]string{"status": "500"}},
			},
		},
		{
			name: "status code filter 2xx passes 200 and 201",
			defs: []APIMetricDefinition{
				{Name: "f.2xx", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "response_code", Label: "status"},
				}, Filters: &MetricFilters{StatusCodes: []string{"2xx"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 201, APIID: "api-1"},
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 404, APIID: "api-1"},
			},
			asserts: []metricAssertion{
				// Only 200 and 201 pass; total sum = 2.
				{Name: "f.2xx", Type: "counter", Sum: 2},
			},
		},
		{
			name: "combined filter requires all conditions to match",
			defs: []APIMetricDefinition{
				{Name: "f.combo", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}, Filters: &MetricFilters{
					APIIDs:      []string{"target-api"},
					Methods:     []string{"GET", "POST"},
					StatusCodes: []string{"2xx"},
				}},
			},
			inputs: []*RequestContext{
				// Matches all: correct API, GET, 200.
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "target-api"},
				// Wrong API.
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "other-api"},
				// Wrong method.
				{Request: httptest.NewRequest(http.MethodDelete, "http://example.com/", nil), StatusCode: 200, APIID: "target-api"},
				// Wrong status.
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 500, APIID: "target-api"},
				// Matches all: correct API, POST, 201.
				{Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 201, APIID: "target-api"},
			},
			asserts: []metricAssertion{
				// Only 2 of 5 requests pass all filter conditions.
				{Name: "f.combo", Type: "counter", Sum: 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, tt.defs)
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Multi-instrument scenarios
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_MultiInstrument(t *testing.T) {
	tests := []struct {
		name    string
		defs    []APIMetricDefinition
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "counter and histogram recorded together",
			defs: []APIMetricDefinition{
				{Name: "hist.total", Type: "histogram", HistogramSource: "total", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
				{Name: "counter.reqs", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
					{Source: "metadata", Key: "api_id", Label: "api_id"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 201, APIID: "multi-api", LatencyTotal: 250},
			},
			asserts: []metricAssertion{
				{Name: "counter.reqs", Type: "counter", Sum: 1, Attrs: map[string]string{"method": "POST", "api_id": "multi-api"}},
				{Name: "hist.total", Type: "histogram", HistCount: 1, HistSum: 0.25, Attrs: map[string]string{"method": "POST"}},
			},
		},
		{
			name: "filtered instrument skips while unfiltered records",
			defs: []APIMetricDefinition{
				{Name: "all.reqs", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}},
				{Name: "target.reqs", Type: "counter", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "method", Label: "method"},
				}, Filters: &MetricFilters{APIIDs: []string{"special-api"}}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "normal-api"},
			},
			asserts: []metricAssertion{
				{Name: "all.reqs", Type: "counter", Sum: 1},
				{Name: "target.reqs", NotPresent: true},
			},
		},
		{
			name: "three histogram latency sources from same request",
			defs: []APIMetricDefinition{
				{Name: "h.total", Type: "histogram", HistogramSource: "total", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "api_id", Label: "api_id"},
				}},
				{Name: "h.gw", Type: "histogram", HistogramSource: "gateway", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "api_id", Label: "api_id"},
				}},
				{Name: "h.up", Type: "histogram", HistogramSource: "upstream", Dimensions: []DimensionDefinition{
					{Source: "metadata", Key: "api_id", Label: "api_id"},
				}},
			},
			inputs: []*RequestContext{
				{Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1",
					LatencyTotal: 200, LatencyGateway: 30, LatencyUpstream: 170},
			},
			asserts: []metricAssertion{
				{Name: "h.total", Type: "histogram", HistCount: 1, HistSum: 0.2},
				{Name: "h.gw", Type: "histogram", HistCount: 1, HistSum: 0.03},
				{Name: "h.up", Type: "histogram", HistCount: 1, HistSum: 0.17},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, tt.defs)
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Table-driven tests: Default api_metrics config (RED instruments)
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_DefaultConfig(t *testing.T) {
	tests := []struct {
		name    string
		inputs  []*RequestContext
		asserts []metricAssertion
	}{
		{
			name: "single GET 200 populates all four default instruments",
			inputs: []*RequestContext{
				{
					Request: httptest.NewRequest(http.MethodGet, "http://example.com/test", nil), StatusCode: 200, APIID: "gw-api",
					Token: "tok-abcdefghij", Session: &user.SessionState{OauthClientID: "oa-1"},
					LatencyTotal: 120, LatencyGateway: 20, LatencyUpstream: 100,
				},
			},
			asserts: []metricAssertion{
				{Name: "http.server.request.duration", Type: "histogram", HistCount: 1, HistSum: 0.12, Attrs: map[string]string{
					"http.request.method": "GET", "http.response.status_code": "200", "tyk.api.id": "gw-api",
				}},
				{Name: "tyk.gateway.request.duration", Type: "histogram", HistCount: 1, HistSum: 0.02, Attrs: map[string]string{
					"http.request.method": "GET", "tyk.api.id": "gw-api",
				}},
				{Name: "tyk.upstream.request.duration", Type: "histogram", HistCount: 1, HistSum: 0.1, Attrs: map[string]string{
					"http.request.method": "GET", "tyk.api.id": "gw-api",
				}},
				{Name: "tyk.api.requests.total", Type: "counter", Sum: 1, Attrs: map[string]string{
					"http.request.method": "GET", "http.response.status_code": "200", "tyk.api.id": "gw-api",
					"tyk.api.key":      "efghij", // truncateKey: last 6 of "tok-abcdefghij"
					"tyk.api.oauth_id": "oa-1",
				}},
			},
		},
		{
			name: "multiple requests accumulate across default instruments",
			inputs: []*RequestContext{
				{
					Request: httptest.NewRequest(http.MethodGet, "http://example.com/", nil), StatusCode: 200, APIID: "api-1",
					LatencyTotal: 500, LatencyGateway: 125, LatencyUpstream: 375,
				},
				{
					Request: httptest.NewRequest(http.MethodPost, "http://example.com/", nil), StatusCode: 201, APIID: "api-1",
					LatencyTotal: 1000, LatencyGateway: 250, LatencyUpstream: 750,
				},
			},
			asserts: []metricAssertion{
				// 2 observations: 0.5 + 1.0 = 1.5s total (exact binary fractions).
				{Name: "http.server.request.duration", Type: "histogram", HistCount: 2, HistSum: 1.5},
				// 2 observations: 0.125 + 0.25 = 0.375s gateway.
				{Name: "tyk.gateway.request.duration", Type: "histogram", HistCount: 2, HistSum: 0.375},
				// 2 observations: 0.375 + 0.75 = 1.125s upstream.
				{Name: "tyk.upstream.request.duration", Type: "histogram", HistCount: 2, HistSum: 1.125},
				// 2 counter increments (different method/status combos create separate data points).
				{Name: "tyk.api.requests.total", Type: "counter", Sum: 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, tp := makeRealRegistry(t, DefaultAPIMetrics())
			ctx := context.Background()
			for _, rc := range tt.inputs {
				reg.RecordAPIMetrics(ctx, rc)
			}
			assertMetrics(t, tp, tt.asserts)
		})
	}
}

// ---------------------------------------------------------------------------
// Edge cases (not table-driven — these test nil/empty safety)
// ---------------------------------------------------------------------------

func TestRecordAPIMetrics_NilRequest(t *testing.T) {
	reg, _ := makeRealRegistry(t, DefaultAPIMetrics())

	// nil RequestContext must not panic.
	require.NotPanics(t, func() {
		reg.RecordAPIMetrics(context.Background(), nil)
	})

	// Non-nil RequestContext with nil Request must not panic.
	rc := &RequestContext{StatusCode: 200, APIID: "api-1"}
	require.NotPanics(t, func() {
		reg.RecordAPIMetrics(context.Background(), rc)
	})
}

func TestRecordAPIMetrics_EmptyRegistry(t *testing.T) {
	reg, _ := makeRealRegistry(t, []APIMetricDefinition{})

	rc := &RequestContext{
		Request:    httptest.NewRequest(http.MethodGet, "http://example.com/", nil),
		StatusCode: 200,
		APIID:      "api-1",
	}

	require.NotPanics(t, func() {
		reg.RecordAPIMetrics(context.Background(), rc)
	})
}

// ---------------------------------------------------------------------------
// Benchmarks use noop provider to measure hot-path overhead (dimension
// extraction, filter matching, pool allocation) without OTel recording cost.
// ---------------------------------------------------------------------------

func BenchmarkRecordAPIMetrics_DefaultInstruments(b *testing.B) {
	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(context.Background()),
	)
	require.NoError(b, err)

	defs := DefaultAPIMetrics()
	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(b, err)

	rc := &RequestContext{
		Request:         httptest.NewRequest(http.MethodGet, "http://example.com/test", nil),
		StatusCode:      200,
		APIID:           "bench-api",
		ListenPath:      "/test",
		Token:           "bench-token-abcdef",
		LatencyTotal:    150,
		LatencyGateway:  50,
		LatencyUpstream: 100,
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.RecordAPIMetrics(ctx, rc)
	}
}

func BenchmarkRecordAPIMetrics_SingleCounter(b *testing.B) {
	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(context.Background()),
	)
	require.NoError(b, err)

	defs := []APIMetricDefinition{
		{
			Name: "bench.counter",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "method"},
				{Source: "metadata", Key: "api_id", Label: "api_id"},
			},
		},
	}
	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(b, err)

	rc := &RequestContext{
		Request:    httptest.NewRequest(http.MethodGet, "http://example.com/test", nil),
		StatusCode: 200,
		APIID:      "bench-api",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.RecordAPIMetrics(ctx, rc)
	}
}

func BenchmarkRecordAPIMetrics_HeaderDimensions(b *testing.B) {
	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(context.Background()),
	)
	require.NoError(b, err)

	defs := []APIMetricDefinition{
		{
			Name: "bench.headers",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "header", Key: "X-Customer-ID", Label: "customer_id"},
				{Source: "header", Key: "X-Tenant", Label: "tenant"},
				{Source: "header", Key: "X-Region", Label: "region"},
			},
		},
	}
	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(b, err)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	r.Header.Set("X-Customer-ID", "cust-42")
	r.Header.Set("X-Tenant", "acme-corp")
	r.Header.Set("X-Region", "us-east-1")

	rc := &RequestContext{
		Request:    r,
		StatusCode: 200,
		APIID:      "bench-api",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.RecordAPIMetrics(ctx, rc)
	}
}

func BenchmarkRecordAPIMetrics_WithFilter(b *testing.B) {
	provider, err := tykmetric.NewProvider(
		tykmetric.WithContext(context.Background()),
	)
	require.NoError(b, err)

	defs := []APIMetricDefinition{
		{
			Name: "bench.filtered",
			Type: "counter",
			Dimensions: []DimensionDefinition{
				{Source: "metadata", Key: "method", Label: "method"},
			},
			Filters: &MetricFilters{
				APIIDs:      []string{"bench-api", "other-api"},
				Methods:     []string{"GET", "POST"},
				StatusCodes: []string{"2xx"},
			},
		},
	}
	reg, err := NewInstrumentRegistry(provider, defs)
	require.NoError(b, err)

	rc := &RequestContext{
		Request:    httptest.NewRequest(http.MethodGet, "http://example.com/test", nil),
		StatusCode: 200,
		APIID:      "bench-api",
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.RecordAPIMetrics(ctx, rc)
	}
}
