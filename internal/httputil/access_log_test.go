package httputil

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"

	"github.com/TykTechnologies/tyk/config"
)

func BenchmarkSuccessLogTransaction(b *testing.B) {
	b.Run("AccessLogs enabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkSuccessLogTransaction(b, conf)

	})
	b.Run("AccessLogs enabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkSuccessLogTransaction(b, conf)
	})
	b.Run("AccessLogs disabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkSuccessLogTransaction(b, conf)
	})
	b.Run("AccessLogs disabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkSuccessLogTransaction(b, conf)
	})
}

func benchmarkSuccessLogTransaction(b *testing.B, conf func(globalConf *config.Config)) {
	b.ReportAllocs()
	b.ResetTimer()

	ts := StartTest(conf)
	defer ts.Close()

	API := BuildAPI(func(spec *APISpec) {
		spec.Name = "test-api"
		spec.APIID = "test-api-id"
		spec.Proxy.ListenPath = "/"
	})[0]

	ts.Gw.LoadAPI(API)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusOK,
		})
	}
}

func BenchmarkErrorLogTransaction(b *testing.B) {
	b.Run("AccessLogs enabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkErrorLogTransaction(b, conf)

	})
	b.Run("AccessLogs enabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = true
		}
		benchmarkErrorLogTransaction(b, conf)
	})

	b.Run("AccessLogs disabled with Hashkeys set to true", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = true
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkErrorLogTransaction(b, conf)
	})

	b.Run("AccessLogs disabled with Hashkeys set to false", func(b *testing.B) {
		conf := func(globalConf *config.Config) {
			globalConf.HashKeys = false
			globalConf.AccessLogs.Enabled = false
		}
		benchmarkErrorLogTransaction(b, conf)
	})
}

func benchmarkErrorLogTransaction(b *testing.B, conf func(globalConf *config.Config)) {
	b.ReportAllocs()

	ts := StartTest(conf)
	defer ts.Close()

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Code: http.StatusNotFound,
		})
	}
}
