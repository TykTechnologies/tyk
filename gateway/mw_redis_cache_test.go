package gateway

import (
	"crypto/md5"
	"encoding/hex"
	"hash"
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestRedisCacheMiddleware_WithCompressedResponse(t *testing.T) {
	const path = "/compressed"

	conf := func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	createAPI := func(withCache bool) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions.CacheTimeout = 60
			spec.CacheOptions.EnableCache = withCache
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.ExtendedPaths.Cached = []string{path}
			})
		})
	}

	t.Run("without cache", func(t *testing.T) {
		createAPI(false)

		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
	})

	t.Run("with cache", func(t *testing.T) {
		createAPI(true)

		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
	})

	t.Run("with cache and  dynamic redis", func(t *testing.T) {
		createAPI(true)
		ts.Gw.RedisController.DisableRedis(true)
		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
		ts.Gw.RedisController.DisableRedis(false)
		ts.Run(t, []test.TestCase{
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
			{Path: path, Code: 200, BodyMatch: "This is a compressed response"},
		}...)
	})

	t.Run("with chunked gzip response body and dynamic redis", func(t *testing.T) {
		createAPI(true)
		ts.Gw.RedisController.DisableRedis(true)
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/chunked", Code: http.StatusOK, BodyMatch: "Mars"},
			{Path: "/chunked", Code: http.StatusOK, BodyMatch: "Mars"},
		}...)
		ts.Gw.RedisController.DisableRedis(false)
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/chunked", Code: http.StatusOK, BodyMatch: "Mars"},
			{Path: "/chunked", Code: http.StatusOK, BodyMatch: "Mars"},
		}...)
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
