package accesslog_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

// accessLogTestCase defines the test inputs.
type accessLogTestCase struct {
	name              string
	hashKeys          bool
	accessLogsEnabled bool
	statusCode        int
}

// accessLogTestCases define test cases in a table to reduce repetition.
func accessLogTestCases(status int) []accessLogTestCase {
	return []accessLogTestCase{
		{"AccessLogs enabled with Hashkeys set to true", true, true, status},
		{"AccessLogs enabled with Hashkeys set to false", false, true, status},
		{"AccessLogs disabled with Hashkeys set to true", true, false, status},
		{"AccessLogs disabled with Hashkeys set to false", false, false, status},
	}
}

// Setup starts the gateway according to test case settings.
func (tt accessLogTestCase) Setup(tb testing.TB) *gateway.Test {
	tb.Helper()

	ts := gateway.StartTest(func(globalConf *config.Config) {
		globalConf.HashKeys = tt.hashKeys
		globalConf.AccessLogs.Enabled = tt.accessLogsEnabled
	})
	tb.Cleanup(ts.Close)

	return ts
}

// Benchmark runs requests against gateway with the benchmark.
func (tt accessLogTestCase) Benchmark(b *testing.B, ts *gateway.Test) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: tt.statusCode,
		})
	}
}

// BenchmarkAccessLog benchmarks access logs for 200 OK.
func BenchmarkAccessLog(b *testing.B) {
	for _, tt := range accessLogTestCases(http.StatusOK) {
		tt := tt // capture range variable
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

// BenchmarkAccessLog benchmarks access logs for 404 Not Found.
func BenchmarkAccessLog_Errors(b *testing.B) {
	for _, tt := range accessLogTestCases(http.StatusNotFound) {
		tt := tt // capture range variable
		b.Run(tt.name, func(b *testing.B) {
			ts := tt.Setup(b)

			tt.Benchmark(b, ts)
		})
	}
}
