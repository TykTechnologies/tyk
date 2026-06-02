package otel_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/test"
)

// otelBenchCase defines the test inputs for OpenTelemetry and analytics benchmarks.
type otelBenchCase struct {
	name         string
	traces       bool
	samplingType string // optional: "AlwaysOn" (default), "AlwaysOff"
	metrics      bool
	analytics    bool
}

// otelBenchCases generates all combinations of traces/metrics/analytics.
func otelBenchCases() []otelBenchCase {
	return []otelBenchCase{
		{"all disabled", false, "", false, false},
		{"traces only", true, "", false, false},
		{"traces sampling=0", true, "AlwaysOff", false, false},
		{"metrics only", false, "", true, false},
		{"analytics only", false, "", false, true},
		{"traces+metrics", true, "", true, false},
		{"traces+analytics", true, "", false, true},
		{"metrics+analytics", false, "", true, true},
		{"all enabled", true, "", true, true},
	}
}

// Setup starts the gateway according to test case settings.
func (tt otelBenchCase) Setup(tb testing.TB) *gateway.Test {
	tb.Helper()

	ts := gateway.StartTest(func(globalConf *config.Config) {
		// Traces: use the new nested format.
		if tt.traces {
			traceCfg := &otel.TracesConfig{
				BaseOpenTelemetry: otel.BaseOpenTelemetry{
					Enabled: true,
				},
			}
			if tt.samplingType != "" {
				traceCfg.Sampling.Type = tt.samplingType
			}
			globalConf.OpenTelemetry.Traces = traceCfg
		}

		// Metrics: Enabled is *bool, must be explicitly set.
		if tt.metrics {
			enabled := true
			globalConf.OpenTelemetry.Metrics.Enabled = &enabled
		}

		// Analytics.
		globalConf.EnableAnalytics = tt.analytics
	})
	tb.Cleanup(ts.Close)

	return ts
}

// Benchmark runs requests against the gateway with the benchmark.
func (tt otelBenchCase) Benchmark(b *testing.B, ts *gateway.Test) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

// BenchmarkOTel benchmarks different observability combinations for 200 OK.
func BenchmarkOTel(b *testing.B) {
	for _, tt := range otelBenchCases() {
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
