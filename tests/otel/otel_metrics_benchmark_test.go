package otel_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/otel/apimetrics"
	"github.com/TykTechnologies/tyk/test"
)

// metricsBenchCase defines test inputs for OTel metrics benchmarks.
type metricsBenchCase struct {
	name           string
	apiMetrics     apimetrics.APIMetricDefinitions // nil=defaults, empty=none, populated=custom
	runtimeMetrics *bool                           // nil=default (true when metrics enabled), explicit otherwise
}

func metricsBenchCases() []metricsBenchCase {
	return []metricsBenchCase{
		{
			name:       "metrics disabled",
			apiMetrics: nil, // sentinel: Setup will not enable metrics
		},
		{
			name:       "defaults (4 instruments)",
			apiMetrics: apimetrics.DefaultAPIMetrics(),
		},
		{
			name:       "no api_metrics (empty)",
			apiMetrics: apimetrics.APIMetricDefinitions{},
		},
		{
			name: "1 counter low-cardinality (2 dims)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name: "bench.requests.total",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
					},
				},
			},
		},
		{
			name: "1 histogram low-cardinality (2 dims)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name:            "bench.request.duration",
					Type:            "histogram",
					HistogramSource: "total",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
					},
				},
			},
		},
		{
			name: "1 counter high-cardinality (6 dims)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name: "bench.requests.total.hc",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "api_name", Label: "tyk.api.name"},
						{Source: "metadata", Key: "org_id", Label: "tyk.org.id"},
						{Source: "metadata", Key: "host", Label: "http.host"},
					},
				},
			},
		},
		{
			name: "1 histogram high-cardinality (6 dims)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name:            "bench.request.duration.hc",
					Type:            "histogram",
					HistogramSource: "total",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "api_name", Label: "tyk.api.name"},
						{Source: "metadata", Key: "org_id", Label: "tyk.org.id"},
						{Source: "metadata", Key: "host", Label: "http.host"},
					},
				},
			},
		},
		{
			name: "1 counter all dimensions (14 dims)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name: "bench.requests.total.all",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						// metadata extractors
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "route", Label: "http.route"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "api_name", Label: "tyk.api.name"},
						{Source: "metadata", Key: "org_id", Label: "tyk.org.id"},
						{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
						{Source: "metadata", Key: "ip_address", Label: "client.address"},
						{Source: "metadata", Key: "api_version", Label: "tyk.api.version"},
						{Source: "metadata", Key: "host", Label: "http.host"},
						{Source: "metadata", Key: "scheme", Label: "url.scheme"},
						// session extractors
						{Source: "session", Key: "api_key", Label: "tyk.api_key"},
						{Source: "session", Key: "oauth_id", Label: "tyk.oauth.client_id"},
						// header extractor
						{Source: "header", Key: "User-Agent", Label: "http.user_agent"},
					},
				},
			},
		},
		{
			name:           "defaults + runtime_metrics=false",
			apiMetrics:     apimetrics.DefaultAPIMetrics(),
			runtimeMetrics: boolPtr(false),
		},
		{
			name:           "defaults + runtime_metrics=true",
			apiMetrics:     apimetrics.DefaultAPIMetrics(),
			runtimeMetrics: boolPtr(true),
		},
		{
			name: "3 counters + 3 histograms (6 instruments)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name:            "bench.total.duration",
					Type:            "histogram",
					HistogramSource: "total",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
					},
				},
				{
					Name:            "bench.gateway.duration",
					Type:            "histogram",
					HistogramSource: "gateway",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
					},
				},
				{
					Name:            "bench.upstream.duration",
					Type:            "histogram",
					HistogramSource: "upstream",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
					},
				},
				{
					Name: "bench.requests.total",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
					},
				},
				{
					Name: "bench.errors.total",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "response_flag", Label: "tyk.response_flag"},
					},
				},
				{
					Name: "bench.bytes.total",
					Type: "counter",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
						{Source: "metadata", Key: "org_id", Label: "tyk.org.id"},
					},
				},
			},
		},
		{
			name: "3 histograms (like defaults, no counter)",
			apiMetrics: apimetrics.APIMetricDefinitions{
				{
					Name:            "bench.total.duration",
					Type:            "histogram",
					HistogramSource: "total",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "response_code", Label: "http.response.status_code"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
					},
				},
				{
					Name:            "bench.gateway.duration",
					Type:            "histogram",
					HistogramSource: "gateway",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
					},
				},
				{
					Name:            "bench.upstream.duration",
					Type:            "histogram",
					HistogramSource: "upstream",
					Dimensions: []apimetrics.DimensionDefinition{
						{Source: "metadata", Key: "method", Label: "http.request.method"},
						{Source: "metadata", Key: "api_id", Label: "tyk.api.id"},
					},
				},
			},
		},
	}
}

// Setup starts the gateway with the given metrics configuration.
// A nil apiMetrics sentinel means metrics are disabled entirely.
func (tt metricsBenchCase) Setup(tb testing.TB) *gateway.Test {
	tb.Helper()

	ts := gateway.StartTest(func(globalConf *config.Config) {
		if tt.apiMetrics == nil {
			// Leave metrics disabled (Enabled stays nil).
			return
		}

		enabled := true
		globalConf.OpenTelemetry.Metrics.Enabled = &enabled
		globalConf.OpenTelemetry.Metrics.APIMetrics = tt.apiMetrics
		if tt.runtimeMetrics != nil {
			globalConf.OpenTelemetry.Metrics.RuntimeMetrics = tt.runtimeMetrics
		}
	})
	tb.Cleanup(ts.Close)

	return ts
}

func boolPtr(v bool) *bool { return &v }

// Benchmark runs requests against the gateway.
func (tt metricsBenchCase) Benchmark(b *testing.B, ts *gateway.Test) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

// BenchmarkOTelMetrics benchmarks different api_metrics configurations.
func BenchmarkOTelMetrics(b *testing.B) {
	for _, tt := range metricsBenchCases() {
		b.Run(tt.name, func(b *testing.B) {
			ts := tt.Setup(b)

			API := gateway.BuildAPI(func(spec *gateway.APISpec) {
				spec.Name = "test-api"
				spec.APIID = "test-api-id"
				spec.Proxy.ListenPath = "/"
			})[0]
			ts.Gw.LoadAPI(API)

			tt.Benchmark(b, ts)
		})
	}
}

// BenchmarkOTelMetrics_WithTraces benchmarks metrics configs with tracing also enabled.
func BenchmarkOTelMetrics_WithTraces(b *testing.B) {
	for _, tt := range metricsBenchCases() {
		b.Run(tt.name, func(b *testing.B) {
			ts := gateway.StartTest(func(globalConf *config.Config) {
				// Always enable traces.
				globalConf.OpenTelemetry.Traces = &otel.TracesConfig{
					BaseOpenTelemetry: otel.BaseOpenTelemetry{
						Enabled: true,
					},
				}

				if tt.apiMetrics != nil {
					enabled := true
					globalConf.OpenTelemetry.Metrics.Enabled = &enabled
					globalConf.OpenTelemetry.Metrics.APIMetrics = tt.apiMetrics
				}
			})
			b.Cleanup(ts.Close)

			API := gateway.BuildAPI(func(spec *gateway.APISpec) {
				spec.Name = "test-api"
				spec.APIID = "test-api-id"
				spec.Proxy.ListenPath = "/"
			})[0]
			ts.Gw.LoadAPI(API)

			tt.Benchmark(b, ts)
		})
	}
}
