package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// decodeAnalyticsRecord is a test helper that flushes analytics, retrieves
// exactly one record from Redis, decodes it, and returns it.
func decodeAnalyticsRecord(t *testing.T, ts *Test) analytics.AnalyticsRecord {
	t.Helper()
	ts.Gw.Analytics.Flush()
	results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)
	require.Len(t, results, 1, "Expected exactly 1 analytics record")

	var record analytics.AnalyticsRecord
	err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
	require.NoError(t, err)
	return record
}

// --- Acceptance Tests (WS-1 and EH-1) ---

func TestOriginalPathAnalytics_WalkingSkeleton(t *testing.T) {
	// WS-1: Full pipeline - strip listen path, verify OriginalPath in analytics record.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/api/v1/"
		spec.Proxy.StripListenPath = true
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/api/v1/users",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, http.StatusOK, record.ResponseCode)
	assert.Equal(t, "/users", record.Path,
		"Path should be the backend path after listen path stripping")
	assert.Equal(t, "/api/v1/users", record.OriginalPath,
		"OriginalPath should be the full client request path before stripping")
	assert.Equal(t, "/api/v1/", record.ListenPath,
		"ListenPath should match the API definition")
}

func TestOriginalPathAnalytics_ErrorHandler_AuthFailure(t *testing.T) {
	// EH-1: Auth failure preserves OriginalPath in error analytics.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false // requires auth
		spec.Proxy.ListenPath = "/api/v1/"
		spec.Proxy.StripListenPath = true
	})

	// No auth header -> 401
	_, _ = ts.Run(t, test.TestCase{
		Path: "/api/v1/secret-data",
		Code: http.StatusUnauthorized,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, http.StatusUnauthorized, record.ResponseCode)
	assert.Equal(t, "/secret-data", record.Path,
		"Path should be stripped for error handler too")
	assert.Equal(t, "/api/v1/secret-data", record.OriginalPath,
		"OriginalPath should capture full client path even on auth failure")
	assert.Equal(t, "/api/v1/", record.ListenPath,
		"ListenPath should match the API definition on error")
}

// --- Unit Tests (SH-1, SH-2, SH-3, EH-2) ---

func TestOriginalPathAnalytics_SuccessHandler(t *testing.T) {
	// SH-1: Success handler populates OriginalPath from context.
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/api/v1/"
		spec.Proxy.StripListenPath = true
	})

	called := false
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		called = true
		assert.Equal(t, "/api/v1/users", record.OriginalPath,
			"OriginalPath should be the full client request path")
		assert.Equal(t, "/api/v1/", record.ListenPath,
			"ListenPath should match the API spec")
		assert.Equal(t, "/users", record.Path,
			"Path should be the stripped backend path")
	}

	_, _ = ts.Run(t, test.TestCase{
		Path: "/api/v1/users",
		Code: http.StatusOK,
	})

	assert.True(t, called, "mockRecordHit should have been invoked")
}

func TestOriginalPathAnalytics_ListenPathMatchesSpec(t *testing.T) {
	// SH-2: ListenPath matches API definition for different APIs.
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/pay/v2/"
		spec.Proxy.StripListenPath = true
	})

	called := false
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
		called = true
		assert.Equal(t, "/pay/v2/", record.ListenPath,
			"ListenPath should reflect the API's configured listen path")
		assert.Equal(t, "/pay/v2/charge", record.OriginalPath,
			"OriginalPath should include the listen path prefix")
	}

	_, _ = ts.Run(t, test.TestCase{
		Path: "/pay/v2/charge",
		Code: http.StatusOK,
	})

	assert.True(t, called, "mockRecordHit should have been invoked")
}

func TestOriginalPathAnalytics_EmptyContextGraceful(t *testing.T) {
	// SH-3: Empty context produces empty OriginalPath without panic.
	// This tests defensive behavior - ctxGetOriginalRequestPath returns ""
	// when the context value was never set, and no panic occurs.
	req, _ := http.NewRequest("GET", "/test", nil)
	got := ctxGetOriginalRequestPath(req)
	assert.Equal(t, "", got, "Empty context should return empty string, not panic")
}

func TestOriginalPathAnalytics_ErrorHandler_ConnectionRefused(t *testing.T) {
	// EH-2: Connection error preserves OriginalPath in error analytics (500).
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/svc/"
		spec.Proxy.StripListenPath = true
		spec.Proxy.TargetURL = "http://localhost:66666" // unreachable
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/svc/health",
		Code: http.StatusInternalServerError,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, http.StatusInternalServerError, record.ResponseCode)
	assert.Equal(t, "/svc/health", record.OriginalPath,
		"OriginalPath should capture full client path even on connection error")
	assert.Equal(t, "/svc/", record.ListenPath,
		"ListenPath should match the API definition on connection error")
}
