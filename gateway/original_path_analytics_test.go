package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/regexp"
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

// --- Integration Tests (INT-2 through INT-7) ---

func TestOriginalPathAnalytics_NoStripPreservesMatchingPaths(t *testing.T) {
	// INT-2: With strip_listen_path=false, OriginalPath and Path should both
	// contain the listen path prefix since nothing is stripped.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/passthrough/"
		spec.Proxy.StripListenPath = false
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/passthrough/data",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, "/passthrough/data", record.OriginalPath,
		"OriginalPath should be the full client request path")
	assert.Equal(t, "/passthrough/data", record.Path,
		"Path should also include listen path prefix when strip is disabled")
	assert.Equal(t, "/passthrough/", record.ListenPath,
		"ListenPath should match the API definition")
}

func TestOriginalPathAnalytics_URLRewritePreservesOriginalPath(t *testing.T) {
	// INT-3: URL rewrite changes the backend path but OriginalPath retains
	// the original client request path before any rewriting.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/old/"
		spec.Proxy.StripListenPath = true

		version := spec.VersionData.Versions["v1"]
		json.Unmarshal([]byte(`{
			"use_extended_paths": true,
			"extended_paths": {
				"url_rewrites": [{
					"path": "/items/",
					"match_pattern": "/items/(.*)",
					"method": "GET",
					"rewrite_to": "/new/v2/items/$1"
				}]
			}
		}`), &version)
		spec.VersionData.Versions["v1"] = version
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/old/items/42",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, "/old/items/42", record.OriginalPath,
		"OriginalPath should be the full client request path before rewrite")
	assert.Equal(t, "/old/", record.ListenPath,
		"ListenPath should match the API definition")
}

func TestOriginalPathAnalytics_CombinedStripAndRewrite(t *testing.T) {
	// INT-4: Combined strip_listen_path + URL rewrite. OriginalPath captures
	// the full client request path regardless of downstream transformations.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/svc/"
		spec.Proxy.StripListenPath = true

		version := spec.VersionData.Versions["v1"]
		json.Unmarshal([]byte(`{
			"use_extended_paths": true,
			"extended_paths": {
				"url_rewrites": [{
					"path": "/alpha/",
					"match_pattern": "/alpha/(.*)",
					"method": "GET",
					"rewrite_to": "/beta/$1"
				}]
			}
		}`), &version)
		spec.VersionData.Versions["v1"] = version
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/svc/alpha/resource",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, "/svc/alpha/resource", record.OriginalPath,
		"OriginalPath should be the full client path before strip and rewrite")
	assert.Equal(t, "/svc/", record.ListenPath,
		"ListenPath should match the API definition")
}

func TestOriginalPathAnalytics_RootListenPath(t *testing.T) {
	// INT-5: Root listen path "/" with strip=true. OriginalPath should capture
	// the full client request path.
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	})
	defer ts.Close()

	ts.Gw.Analytics.Flush()
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.StripListenPath = true
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/health",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, "/health", record.OriginalPath,
		"OriginalPath should capture full path even with root listen path")
	assert.Equal(t, "/", record.ListenPath,
		"ListenPath should be root")
}

func TestOriginalPathAnalytics_URLEncodedPath(t *testing.T) {
	// INT-6: URL-encoded characters in the path are preserved in OriginalPath.
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
		Path: "/api/v1/users/Mar%C3%ADa%20Santos",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Contains(t, record.OriginalPath, "/api/v1/users/Mar",
		"OriginalPath should contain the URL-encoded path prefix")
	assert.Equal(t, "/api/v1/", record.ListenPath,
		"ListenPath should match the API definition")
}

func TestOriginalPathAnalytics_TrailingSlashPreserved(t *testing.T) {
	// INT-7: Trailing slash in the request path is preserved in OriginalPath.
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
		Path: "/api/v1/users/",
		Code: http.StatusOK,
	})

	record := decodeAnalyticsRecord(t, ts)

	assert.Equal(t, "/api/v1/users/", record.OriginalPath,
		"OriginalPath should preserve trailing slash")
	assert.Equal(t, "/api/v1/", record.ListenPath,
		"ListenPath should match the API definition")
}

// --- Backward Compatibility Tests (BC-1, BC-2) ---

func TestOriginalPathAnalytics_BackwardCompat_PathAndRawPathUnchanged(t *testing.T) {
	// BC-1: Path and RawPath fields remain identical to pre-feature behavior.
	// Adding OriginalPath must not alter how Path and RawPath are recorded.
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

	// Path should be the stripped backend path (pre-existing behavior)
	assert.Equal(t, "/users", record.Path,
		"Path must remain the backend path after listen path stripping (backward compat)")
	// RawPath should also be the stripped path (pre-existing behavior)
	assert.Equal(t, "/users", record.RawPath,
		"RawPath must remain the backend path (backward compat)")
	// OriginalPath is the new field — it should NOT affect Path or RawPath
	assert.Equal(t, "/api/v1/users", record.OriginalPath,
		"OriginalPath is additive and should not alter existing fields")
}

func TestOriginalPathAnalytics_BackwardCompat_NormalisePathDoesNotAffectOriginalPath(t *testing.T) {
	// BC-2: NormalisePath modifies record.Path but must not modify record.OriginalPath.
	// NormalisePath was written before OriginalPath existed and only operates on Path.
	uuid := "ca761232-ed42-11ce-bacd-00aa0057b223"

	record := analytics.AnalyticsRecord{
		Path:         "/users/" + uuid + "/orders",
		RawPath:      "/users/" + uuid + "/orders",
		OriginalPath: "/api/v1/users/" + uuid + "/orders",
	}

	cfg := &config.Config{}
	cfg.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
	cfg.AnalyticsConfig.NormaliseUrls.CompiledPatternSet.UUIDs = regexp.MustCompile(
		`[0-9a-fA-F]{8}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{12}`,
	)

	NormalisePath(&record, cfg)

	assert.Equal(t, "/users/{uuid}/orders", record.Path,
		"NormalisePath should replace UUID in Path for aggregate analytics")
	assert.Equal(t, "/api/v1/users/"+uuid+"/orders", record.OriginalPath,
		"NormalisePath must NOT modify OriginalPath — it preserves the exact client request path")
}
