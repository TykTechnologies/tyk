package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func testPrepareResponseHeaderInjection(ts *Test) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			json.Unmarshal([]byte(`[
				{
					"delete_headers": ["X-Tyk-Test"],
					"add_headers": {"X-Test": "test"},
					"path": "/test-with-slash",
					"method": "GET",
					"act_on": false
				},
				{
					"delete_headers": ["X-Tyk-Test"],
					"add_headers": {"X-Test": "test"},
					"path": "test-no-slash",
					"method": "GET",
					"act_on": false
				},
				{
					"delete_headers": ["X-Tyk-Test"],
					"add_headers": {"X-Test": "test"},
					"path": "/rewrite-test",
					"method": "GET",
					"act_on": false
				}
			]`), &v.ExtendedPaths.TransformResponseHeader)
			json.Unmarshal([]byte(`[
				{
					"delete_headers": ["User-Agent"],
					"add_headers": {"X-I-Am": "Request"},
					"path": "/rewrite-test",
					"method": "GET",
					"act_on": false
				}
			]`), &v.ExtendedPaths.TransformHeader)

			v.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
				Path:         "/rewrite-test",
				Method:       "GET",
				MatchPattern: "rewrite-test",
				RewriteTo:    "newpath",
			}}
		})
		spec.ResponseProcessors = []apidef.ResponseProcessor{{Name: "header_injector"}}

		spec.CacheOptions = apidef.CacheOptions{
			EnableCache:                cacheEnabled,
			EnableUpstreamCacheControl: true,
			CacheTimeout:               60,
			CacheAllSafeRequests:       true,
		}
	})
}

func TestResponseHeaderInjection(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testPrepareResponseHeaderInjection(ts)

	addHeaders := map[string]string{
		"X-Test": "test",
	}
	addHeadersCached := map[string]string{
		"X-Test":             "test",
		cachedResponseHeader: "1",
	}

	deleteHeaders := map[string]string{
		"X-Tyk-Test":         "1",
		cachedResponseHeader: "1",
	}
	deleteHeadersCached := map[string]string{
		"X-Tyk-Test": "1",
	}

	userAgent := fmt.Sprintf("\"User-Agent\":\"Tyk/%v\"", VERSION)

	_, _ = ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
		{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"Url":"/newpath"`},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeadersCached, BodyMatch: `"X-I-Am":"Request"`},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeadersCached, BodyMatch: userAgent},
	}...)
}

func BenchmarkResponseHeaderInjection(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	testPrepareResponseHeaderInjection(ts)

	addHeaders := map[string]string{
		"X-Test": "test",
	}
	addHeadersCached := map[string]string{
		"X-Test":             "test",
		cachedResponseHeader: "1",
	}

	deleteHeaders := map[string]string{
		"X-Tyk-Test":         "1",
		cachedResponseHeader: "1",
	}
	deleteHeadersCached := map[string]string{
		"X-Tyk-Test": "1",
	}

	userAgent := fmt.Sprintf("\"User-Agent\":\"Tyk/%v\"", VERSION)

	for i := 0; i < b.N; i++ {
		_, _ = ts.Run(b, []test.TestCase{
			// Create base auth based key
			{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"Url":"/newpath"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeadersCached, BodyMatch: `"X-I-Am":"Request"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeadersCached, BodyMatch: userAgent},
		}...)
	}
}

func TestGlobalResponseHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"

		spec.ResponseProcessors = []apidef.ResponseProcessor{{Name: "header_injector"}}

	})[0]
	ts.Gw.LoadAPI(spec)

	addedHeaders := map[string]string{"X-Tyk-Test": "1"}
	removedHeaders := map[string]string{}

	_, _ = ts.Run(t, test.TestCase{HeadersMatch: addedHeaders, HeadersNotMatch: removedHeaders})

	// Add and remove global response headers
	UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
		v.UseExtendedPaths = true
		v.GlobalResponseHeaders = map[string]string{
			"global-header": "global-value",
		}
		v.GlobalResponseHeadersRemove = []string{"X-Tyk-Test"}
	})
	ts.Gw.LoadAPI(spec)

	addedHeaders = map[string]string{"global-header": "global-value"}
	removedHeaders = map[string]string{"X-Tyk-Test": "1"}

	_, _ = ts.Run(t, test.TestCase{HeadersMatch: addedHeaders, HeadersNotMatch: removedHeaders})
}
