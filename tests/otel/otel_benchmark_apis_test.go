package otel_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

// BenchmarkOTelMetrics_APICount benchmarks default RED metrics
// as the number of loaded APIs increases (1, 25, 50, 100, 500, 1000).
// Requests are distributed round-robin so every API generates metric time series.
//
// Metrics export to a real OTel collector on localhost:4317 (grpc) with a 5s
// export interval. Use benchtime=11s so each sub-benchmark covers 2 full
// export cycles, capturing recording + serialization + gRPC export contention.
func BenchmarkOTelMetrics_APICount(b *testing.B) {
	counts := []int{1, 25, 50, 100, 500, 1000}
	for _, metricsEnabled := range []bool{false, true} {
		label := "metrics_disabled"
		if metricsEnabled {
			label = "metrics_enabled"
		}
		b.Run(label, func(b *testing.B) {
			for _, n := range counts {
				b.Run(fmt.Sprintf("%d_apis", n), func(b *testing.B) {
					ts := gateway.StartTest(func(globalConf *config.Config) {
						if metricsEnabled {
							enabled := true
							globalConf.OpenTelemetry.Metrics.Enabled = &enabled
							globalConf.OpenTelemetry.Metrics.Exporter = "grpc"
							globalConf.OpenTelemetry.Metrics.Endpoint = "localhost:4317"
							globalConf.OpenTelemetry.Metrics.ExportInterval = 5
						}
					})
					b.Cleanup(ts.Close)

					builders := make([]func(*gateway.APISpec), n)
					paths := make([]string, n)
					for i := range builders {
						idx := i
						paths[idx] = fmt.Sprintf("/api-%d/", idx)
						builders[idx] = func(spec *gateway.APISpec) {
							spec.Name = fmt.Sprintf("bench-api-%d", idx)
							spec.APIID = fmt.Sprintf("bench-api-%d", idx)
							spec.Proxy.ListenPath = paths[idx]
						}
					}
					ts.Gw.LoadAPI(gateway.BuildAPI(builders...)...)

					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						ts.Run(b, test.TestCase{
							Path: paths[i%n],
							Code: http.StatusOK,
						})
					}
				})
			}
		})
	}
}
