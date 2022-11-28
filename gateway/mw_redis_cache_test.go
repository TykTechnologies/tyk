package gateway

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestRedisCacheMiddlewareUnit(t *testing.T) {
	testcases := []struct {
		Name string
		Fn   func(t *testing.T)
	}{
		{
			Name: "isTimeStampExpired",
			Fn: func(t *testing.T) {
				mw := &RedisCacheMiddleware{}

				assert.True(t, mw.isTimeStampExpired("invalid"))
				assert.True(t, mw.isTimeStampExpired("1"))
				assert.True(t, mw.isTimeStampExpired(fmt.Sprint(time.Now().Unix()-60)))
				assert.False(t, mw.isTimeStampExpired(fmt.Sprint(time.Now().Unix()+60)))
			},
		},
		{
			Name: "decodePayload",
			Fn: func(t *testing.T) {
				mw := &RedisCacheMiddleware{}

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
			ts.Gw.RedisController.DisableRedis(true)
			subCheck(t, false, p)

			ts.Gw.RedisController.DisableRedis(false)
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
				t.Errorf("addBodyHash() recieved = %v, expected %v", hex.EncodeToString(tt.args.h.Sum(nil)), tt.expected)
			}
		})
	}
}
