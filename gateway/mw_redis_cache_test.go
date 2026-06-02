package gateway

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/opentelemetry/metric/metrictest"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestRedisCacheMiddlewareUnit(t *testing.T) {
	testcases := []struct {
		Name string
		Fn   func(t *testing.T)
	}{
		{
			Name: "isTimeStampExpired",
			Fn: func(t *testing.T) {
				t.Helper()
				mw := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{}}

				assert.True(t, mw.isTimeStampExpired("invalid"))
				assert.True(t, mw.isTimeStampExpired("1"))
				assert.True(t, mw.isTimeStampExpired(fmt.Sprint(time.Now().Unix()-60)))
				assert.False(t, mw.isTimeStampExpired(fmt.Sprint(time.Now().Unix()+60)))
			},
		},
		{
			Name: "decodePayload",
			Fn: func(t *testing.T) {
				t.Helper()
				mw := &RedisCacheMiddleware{BaseMiddleware: &BaseMiddleware{}}

				if data, expire, err := mw.decodePayload("dGVzdGluZwo=|123"); true {
					assert.Equal(t, "testing\n", data)
					assert.Equal(t, "123", expire)
					assert.NoError(t, err)
				}

				if _, _, err := mw.decodePayload("payload|a|b|c"); true {
					assert.Error(t, err)
				}

				if data, _, err := mw.decodePayload("payload"); true {
					assert.Equal(t, "payload", data)
					assert.NoError(t, err)
				}
			},
		},
		{
			Name: "encodePayload",
			Fn: func(t *testing.T) {
				t.Helper()
				mw := &ResponseCacheMiddleware{}

				result := mw.encodePayload("test", 123)

				assert.True(t, strings.HasSuffix(result, "|123"))
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, tc.Fn)
	}
}

func TestRedisCacheMiddleware(t *testing.T) {
	conf := func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	ts.Gw.Analytics.mockEnabled = true
	defer func() {
		ts.Gw.Analytics.mockEnabled = false
	}()

	const compressed = "/compressed"
	const chunked = "/chunked"
	createAPI := func(withCache bool) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.CacheOptions.EnableCache = withCache
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.Cached = []string{compressed, chunked}
			})
		})
	}

	type params struct {
		path             string
		bodyMatch        string
		uncompressed     bool
		transferEncoding []string
	}

	check := func(t *testing.T, p params) {
		subCheck := func(t *testing.T, cachingActive bool, p params) {
			t.Helper()
			headersMatch := make(map[string]string)
			if cachingActive {
				headersMatch["x-tyk-cached-response"] = "1"
				p.transferEncoding = nil
			}

			ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
				response, err := base64.StdEncoding.DecodeString(record.RawResponse)
				assert.NoError(t, err)

				assert.Contains(t, string(response), p.bodyMatch)
			}

			resp, _ := ts.Run(t, []test.TestCase{
				{Path: p.path, BodyMatch: p.bodyMatch, Code: http.StatusOK},
				{Path: p.path, HeadersMatch: headersMatch, BodyMatch: p.bodyMatch, Code: http.StatusOK},
			}...)

			assert.Equal(t, p.transferEncoding, resp.TransferEncoding)
			assert.Equal(t, p.uncompressed, resp.Uncompressed)
		}

		t.Run("without cache", func(t *testing.T) {
			createAPI(false)
			subCheck(t, false, p)
		})

		t.Run("with cache", func(t *testing.T) {
			createAPI(true)
			subCheck(t, true, p)
		})

		t.Run("with cache and dynamic redis", func(t *testing.T) {
			createAPI(true)
			ts.Gw.StorageConnectionHandler.DisableStorage(true)
			subCheck(t, false, p)

			ts.Gw.StorageConnectionHandler.DisableStorage(false)
			subCheck(t, true, p)
		})
	}

	t.Run("compressed", func(t *testing.T) {
		check(t, params{
			path:             compressed,
			bodyMatch:        "This is a compressed response",
			uncompressed:     true,
			transferEncoding: nil,
		})
	})

	t.Run("chunked", func(t *testing.T) {
		check(t, params{
			path:             chunked,
			bodyMatch:        "This is a chunked response",
			uncompressed:     false,
			transferEncoding: []string{"chunked"},
		})
	})
}

func TestRedisCacheMiddlewareV2(t *testing.T) {
	const compressed = "/compressed"
	const chunked = "/chunked"

	type testcase struct {
		title         string
		useCaching    bool
		useCompressed bool
		useChunked    bool
	}

	bools := []bool{false, true}

	testcases := make([]testcase, 0, 1<<3)
	for _, useCaching := range bools {
		for _, useCompressed := range bools {
			for _, useChunked := range bools {
				if useChunked == useCompressed {
					continue
				}

				testcases = append(testcases, testcase{
					title:         fmt.Sprintf("cache=%v, chunked=%v, compressed=%v", useCaching, useChunked, useCompressed),
					useCaching:    useCaching,
					useChunked:    useChunked,
					useCompressed: useCompressed,
				})
			}
		}
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.title, func(t *testing.T) {
			conf := func(globalConf *config.Config) {
				globalConf.AnalyticsConfig.EnableDetailedRecording = true
			}
			ts := StartTest(conf)
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/"
				spec.CacheOptions.CacheTimeout = 60
				spec.CacheOptions.EnableCache = tc.useCaching

				if tc.useCaching {
					UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
						v.ExtendedPaths.Cached = []string{compressed, chunked}
					})
				}
			})

			var url, bodyMatch string
			var wantHeaders map[string]string

			if tc.useChunked {
				url = "/chunked"
				bodyMatch = "This is a chunked response"
			}
			if tc.useCompressed {
				url = "/compressed"
				bodyMatch = "This is a compressed response"
			}
			if tc.useCaching {
				wantHeaders = map[string]string{
					"x-tyk-cached-response": "1",
				}
			}

			assert.NotEmpty(t, url)

			ts.Gw.Analytics.mockEnabled = true
			ts.Gw.Analytics.mockRecordHit = func(record *analytics.AnalyticsRecord) {
				response, err := base64.StdEncoding.DecodeString(record.RawResponse)
				assert.NoError(t, err)

				assert.Contains(t, string(response), bodyMatch)
			}

			defer func() {
				ts.Gw.Analytics.mockEnabled = false
			}()

			resp, _ := ts.Run(t, []test.TestCase{
				{Path: url, BodyMatch: bodyMatch, Code: http.StatusOK},
				{Path: url, HeadersMatch: wantHeaders, BodyMatch: bodyMatch, Code: http.StatusOK},
			}...)

			if tc.useChunked {
				if tc.useCaching {
					var empty []string
					assert.Equal(t, empty, resp.TransferEncoding)
				} else {
					assert.Equal(t, []string{"chunked"}, resp.TransferEncoding)
				}
			}

			if tc.useCompressed {
				assert.True(t, resp.Uncompressed)
			}
		})
	}
}

func TestRedisCacheMiddleware_RateLimitHeaders(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.RateLimitResponseHeaders = config.SourceQuotas
	})
	defer ts.Close()

	ts.AddDynamicHandler("upstream-with-rl-headers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(header.XRateLimitLimit, "999")
		w.Header().Set(header.XRateLimitRemaining, "998")
		w.Header().Set(header.XRateLimitReset, "1234567890")
		w.WriteHeader(http.StatusOK)
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/cache-rl-test"
		spec.Proxy.TargetURL = TestHttpAny + "/upstream-with-rl-headers"
		spec.Proxy.StripListenPath = true
		spec.UseKeylessAccess = false

		spec.CacheOptions.CacheTimeout = 60
		spec.CacheOptions.EnableCache = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			// Matching the stripped listen path and all subpaths
			v.ExtendedPaths.Cached = []string{"/(.*)"}
		})
	})[0]

	_, authKey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			api.APIID: {
				APIName: api.Name,
				APIID:   api.APIID,
				Limit: user.APILimit{
					QuotaMax:         10,
					QuotaRenewalRate: 60,
				},
			},
		}
	})

	authHeader := map[string]string{header.Authorization: authKey}

	resp1, _ := ts.Run(t, []test.TestCase{
		{
			Headers: authHeader,
			Path:    "/cache-rl-test",
			Code:    http.StatusOK,
			HeadersNotMatch: map[string]string{
				cachedResponseHeader: "1",
			},
		},
	}...)

	assert.Equal(t, "10", resp1.Header.Get(header.XRateLimitLimit))
	assert.Equal(t, "9", resp1.Header.Get(header.XRateLimitRemaining))
	assert.Len(t, resp1.Header.Values(header.XRateLimitLimit), 1)

	resp2, _ := ts.Run(t, []test.TestCase{
		{
			Headers: authHeader,
			Path:    "/cache-rl-test",
			Code:    http.StatusOK,
			HeadersMatch: map[string]string{
				cachedResponseHeader: "1",
			},
		},
	}...)

	assert.Equal(t, "10", resp2.Header.Get(header.XRateLimitLimit))
	assert.Equal(t, "8", resp2.Header.Get(header.XRateLimitRemaining))
	assert.Len(t, resp2.Header.Values(header.XRateLimitLimit), 1)
}

func Test_isSafeMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		expected bool
	}{
		{"Test if Get is a safe method", http.MethodGet, true},
		{"Test if Head is a safe method", http.MethodHead, true},
		{"Test if Options is a safe method", http.MethodOptions, true},
		{"Test if Post is a safe method", http.MethodPost, false},
		{"Test if Put is a safe method", http.MethodPut, false},
		{"Test if Patch is a safe method", http.MethodPatch, false},
		{"Test if Delete is a safe method", http.MethodDelete, false},
		{"Test if Connect is a safe method", http.MethodConnect, false},
		{"Test if Trace is a safe method", http.MethodTrace, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSafeMethod(tt.method); got != tt.expected {
				t.Errorf("isSafeMethod() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func Test_isBodyHashRequired(t *testing.T) {
	requestPutNoBody, _ := http.NewRequest(http.MethodPut, "http://test.com", nil)
	requestGetNoBody, _ := http.NewRequest(http.MethodGet, "http://test.com", nil)
	requestPutWithBody, _ := http.NewRequest(http.MethodPut, "http://test.com", strings.NewReader("some-body"))
	requestPostWithBody, _ := http.NewRequest(http.MethodPost, "http://test.com", strings.NewReader("some-body"))
	requestPatchWithBody, _ := http.NewRequest(http.MethodPatch, "http://test.com", strings.NewReader("some-body"))
	requestGetWithBody, _ := http.NewRequest(http.MethodGet, "http://test.com", strings.NewReader("some-body"))
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name     string
		args     args
		expected bool
	}{
		{"Put no body", args{requestPutNoBody}, false},
		{"Get no body", args{requestGetNoBody}, false},
		{"Get with body", args{requestGetWithBody}, false},
		{"Put with body", args{requestPutWithBody}, true},
		{"Post with body", args{requestPostWithBody}, true},
		{"Patch with body", args{requestPatchWithBody}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBodyHashRequired(tt.args.request); got != tt.expected {
				t.Errorf("isBodyHashRequired() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func Test_addBodyHash(t *testing.T) {
	requestPutNoBody, _ := http.NewRequest(http.MethodPut, "http://test.com", nil)
	requestPostWithBody, _ := http.NewRequest(http.MethodPost, "http://test.com", strings.NewReader("some-body"))
	requestPatchWithBody, _ := http.NewRequest(http.MethodPatch, "http://test.com", strings.NewReader("{\"id\":\"1\",\"name\":\"test\"}"))
	type args struct {
		req   *http.Request
		regex string
		h     hash.Hash
	}
	tests := []struct {
		name     string
		args     args
		expected string
	}{
		{"No body", args{requestPutNoBody, ".*", md5.New()}, "d41d8cd98f00b204e9800998ecf8427e"},
		{"Hash the entire body by regexp", args{requestPostWithBody, ".*", md5.New()}, "2838333d94b3b7114a3cabdf4e4fadf4"},
		{"Hash the entire body no regexp", args{requestPostWithBody, "", md5.New()}, "2838333d94b3b7114a3cabdf4e4fadf4"},
		{"Hash by id regexp", args{requestPatchWithBody, "\"id\":[^,]*", md5.New()}, "abe7ef0275f752342a4bf370afb0be2b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if addBodyHash(tt.args.req, tt.args.regex, tt.args.h); hex.EncodeToString(tt.args.h.Sum(nil)) != tt.expected {
				t.Errorf("addBodyHash() received = %v, expected %v", hex.EncodeToString(tt.args.h.Sum(nil)), tt.expected)
			}
		})
	}
}

// TestRedisCacheMiddleware_Observability verifies that cache hits produce
// the same observability signals as regular (non-cached) requests:
// analytics (RecordHit), access logs (RecordAccessLog), and OTel metrics (RecordMetrics).
func TestRedisCacheMiddleware_Observability(t *testing.T) {
	// Install a test hook on the global logger to capture access log entries.
	hook := &logrustest.Hook{}
	log.AddHook(hook)
	defer log.ReplaceHooks(make(logrus.LevelHooks))

	ts := StartTest(nil)
	defer ts.Close()

	// StartTest sets log level to Error when TYK_LOGLEVEL is unset.
	// Access logs are emitted at Info level, so we must restore it.
	origLevel := log.GetLevel()
	log.SetLevel(logrus.InfoLevel)
	defer log.SetLevel(origLevel)

	// Enable access logs.
	gwConfig := ts.Gw.GetConfig()
	gwConfig.AccessLogs.Enabled = true
	ts.Gw.SetConfig(gwConfig)

	// Track analytics RecordHit calls.
	var analyticsCount atomic.Int32
	ts.Gw.Analytics.mockEnabled = true
	ts.Gw.Analytics.mockRecordHit = func(_ *analytics.AnalyticsRecord) {
		analyticsCount.Add(1)
	}
	defer func() {
		ts.Gw.Analytics.mockEnabled = false
	}()

	// Build API with caching enabled on /cached path.
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.CacheOptions.CacheTimeout = 60
		spec.CacheOptions.EnableCache = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.Cached = []string{"/cached"}
		})
	})

	// Sanity: verify the hook captures Info entries from the gateway logger.
	hook.Reset()
	log.WithField("status", 200).Info("sanity check")
	require.Equal(t, 1, len(hook.AllEntries()), "hook sanity check: should capture log entries")
	hook.Reset()

	// --- Request 1: cache miss (goes through SuccessHandler) ---

	// Install a real metrics provider so we can read the tyk.http.requests counter.
	missTP := metrictest.NewProvider(t)
	ts.Gw.MetricInstruments = otel.NewMetricInstruments(missTP, logrus.New())

	ts.Run(t, test.TestCase{
		Path: "/cached",
		Code: http.StatusOK,
		HeadersNotMatch: map[string]string{
			"x-tyk-cached-response": "1",
		},
	})

	missAnalyticsCount := analyticsCount.Load()
	missAccessLogCount := countAccessLogEntries(hook)

	require.Equal(t, int32(1), missAnalyticsCount, "cache miss: expected 1 analytics RecordHit call")
	require.Equal(t, 1, missAccessLogCount, "cache miss: expected 1 access log entry")

	// Verify RecordMetrics was called (it calls RecordRequest which increments tyk.http.requests).
	missMetric := missTP.FindMetric(t, "tyk.http.requests")
	metrictest.AssertSum(t, missMetric, int64(1))

	// --- Request 2: cache hit (served by RedisCacheMiddleware, chain short-circuited) ---
	hook.Reset()
	analyticsCount.Store(0)

	// Fresh metrics provider for the cache hit request.
	hitTP := metrictest.NewProvider(t)
	ts.Gw.MetricInstruments = otel.NewMetricInstruments(hitTP, logrus.New())

	ts.Run(t, test.TestCase{
		Path: "/cached",
		Code: http.StatusOK,
		HeadersMatch: map[string]string{
			"x-tyk-cached-response": "1",
		},
	})

	hitAnalyticsCount := analyticsCount.Load()
	hitAccessLogCount := countAccessLogEntries(hook)

	// Analytics (RecordHit) works for cache hits — the cache middleware calls it directly.
	assert.Equal(t, int32(1), hitAnalyticsCount, "cache hit: expected 1 analytics RecordHit call")

	// RecordAccessLog is called on cache hits.
	assert.Equal(t, 1, hitAccessLogCount, "cache hit: expected 1 access log entry")

	// RecordMetrics (OTel) is called on cache hits.
	hitMetric := hitTP.FindMetric(t, "tyk.http.requests")
	metrictest.AssertSum(t, hitMetric, int64(1))
}

// countAccessLogEntries counts log entries with prefix "access-log"
// (set by accesslog.NewRecord in internal/httputil/accesslog/record.go:26).
func countAccessLogEntries(hook *logrustest.Hook) int {
	count := 0
	for _, entry := range hook.AllEntries() {
		if entry.Data["prefix"] == "access-log" {
			count++
		}
	}
	return count
}
