package accesslog

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func BenchmarkSuccessLogTransaction(b *testing.B) {
	// Define test cases in a table to reduce repetition
	tests := []struct {
		name              string
		hashKeys          bool
		accessLogsEnabled bool
		statusCode        int
	}{
		{"AccessLogs enabled with Hashkeys set to true", true, true, http.StatusOK},
		{"AccessLogs enabled with Hashkeys set to false", false, true, http.StatusOK},
		{"AccessLogs disabled with Hashkeys set to true", true, false, http.StatusOK},
		{"AccessLogs disabled with Hashkeys set to false", false, false, http.StatusOK},
	}

	// Loop through each test case
	for _, tt := range tests {
		tt := tt // capture range variable
		b.Run(tt.name, func(b *testing.B) {
			conf := func(globalConf *config.Config) {
				globalConf.HashKeys = tt.hashKeys
				globalConf.AccessLogs.Enabled = tt.accessLogsEnabled
			}
			ts := gateway.StartTest(conf)

			// Cleanup should be called instead of defer
			b.Cleanup(func() {
				ts.Close()
			})

			API := gateway.BuildAPI(func(spec *gateway.APISpec) {
				spec.Name = "test-api"
				spec.APIID = "test-api-id"
				spec.Proxy.ListenPath = "/"
			})[0]

			ts.Gw.LoadAPI(API)
			benchmarkSuccessLogTransaction(b, ts, tt.statusCode)
		})
	}
}

func benchmarkSuccessLogTransaction(b *testing.B, ts *gateway.Test, statusCode int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: statusCode,
		})
	}
}

func BenchmarkErrorLogTransaction(b *testing.B) {
	// Define test cases in a table to reduce repetition
	tests := []struct {
		name              string
		hashKeys          bool
		accessLogsEnabled bool
		statusCode        int
	}{
		{"AccessLogs enabled with Hashkeys set to true", true, true, http.StatusNotFound},
		{"AccessLogs enabled with Hashkeys set to false", false, true, http.StatusNotFound},
		{"AccessLogs disabled with Hashkeys set to true", true, false, http.StatusNotFound},
		{"AccessLogs disabled with Hashkeys set to false", false, false, http.StatusNotFound},
	}

	// Loop through each test case
	for _, tt := range tests {
		tt := tt // capture range variable
		b.Run(tt.name, func(b *testing.B) {
			conf := func(globalConf *config.Config) {
				globalConf.HashKeys = tt.hashKeys
				globalConf.AccessLogs.Enabled = tt.accessLogsEnabled
			}
			ts := gateway.StartTest(conf)

			// Cleanup should be called instead of defer
			b.Cleanup(func() {
				ts.Close()
			})

			benchmarkErrorLogTransaction(b, ts, tt.statusCode)
		})
	}
}

func benchmarkErrorLogTransaction(b *testing.B, ts *gateway.Test, statusCode int) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: statusCode,
		})
	}
}
