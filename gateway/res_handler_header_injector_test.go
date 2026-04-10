package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func testPrepareResponseHeaderInjection(ts *Test) {
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
		spec.DisableRateLimit = true
		spec.DisableQuota = true
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
				},
				{
					"disabled": true,
					"delete_headers": ["X-Tyk-Test"],
					"add_headers": {"X-Test": "test"},
					"path": "/disabled",
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
				},
				{
					"disabled": true,
					"delete_headers": ["User-Agent"],
					"add_headers": {"X-I-Am": "Request"},
					"path": "/disabled",
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
		{Method: "GET", Path: "/disabled", HeadersNotMatch: addHeaders, HeadersMatch: deleteHeadersCached, BodyNotMatch: `"X-I-Am":"Request"`},
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
		"X-Tyk-Test": "1",
	}

	userAgent := fmt.Sprintf("\"User-Agent\":\"Tyk/%v\"", VERSION)

	for i := 0; i < b.N; i++ {
		_, _ = ts.Run(b, []test.TestCase{
			// Create base auth based key
			{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"Url":"/newpath"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeaders, BodyMatch: `"X-I-Am":"Request"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeadersCached, HeadersNotMatch: deleteHeaders, BodyMatch: userAgent},
		}...)

		// It's a loop, first time won't be cached.
		addHeaders[cachedResponseHeader] = "1"
	}
}

func TestGlobalResponseHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
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

	t.Run("disabled", func(t *testing.T) {
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.GlobalResponseHeadersDisabled = true
		})
		ts.Gw.LoadAPI(spec)

		_, _ = ts.Run(t, test.TestCase{HeadersNotMatch: addedHeaders, HeadersMatch: removedHeaders})
	})
}

func TestLegacyHeaderInjectorWithResponseProcessorOptions(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
	})[0]

	addedHeaders := map[string]string{"X-Tyk-Test": "1"}
	removedHeaders := map[string]string{}
	_, _ = ts.Run(t, test.TestCase{HeadersMatch: addedHeaders, HeadersNotMatch: removedHeaders})

	api.ResponseProcessors = []apidef.ResponseProcessor{
		{
			Name: "header_injector",
			Options: map[string]interface{}{
				"add_headers":    map[string]string{"global-header": "global-value"},
				"remove_headers": []string{"X-Tyk-Test"},
			},
		},
	}
	ts.Gw.LoadAPI(api)

	addedHeaders = map[string]string{"global-header": "global-value"}
	removedHeaders = map[string]string{"X-Tyk-Test": "1"}
	_, _ = ts.Run(t, test.TestCase{HeadersMatch: addedHeaders, HeadersNotMatch: removedHeaders})
}

func TestHeaderInjector_Enabled(t *testing.T) {
	versionInfo := apidef.VersionInfo{
		GlobalResponseHeaders: map[string]string{},
	}

	versions := map[string]apidef.VersionInfo{
		"Default": versionInfo,
	}

	hi := HeaderInjector{}
	hi.Spec = &APISpec{APIDefinition: &apidef.APIDefinition{}}
	hi.Spec.VersionData.Versions = versions

	assert.False(t, hi.Enabled())

	// version level add headers
	versionInfo.GlobalResponseHeaders["a"] = "b"
	assert.True(t, versionInfo.GlobalResponseHeadersEnabled())
	assert.True(t, hi.Enabled())

	versionInfo.GlobalResponseHeaders = nil
	versions["Default"] = versionInfo
	assert.False(t, hi.Enabled())

	// endpoint level add headers
	versionInfo.UseExtendedPaths = true
	versionInfo.ExtendedPaths.TransformResponseHeader = []apidef.HeaderInjectionMeta{{Disabled: false, DeleteHeaders: []string{"a"}}}
	versions["Default"] = versionInfo
	assert.True(t, hi.Enabled())
}

func TestVersionInfo_GlobalResponseHeadersEnabled(t *testing.T) {
	v := apidef.VersionInfo{
		GlobalResponseHeaders:       map[string]string{},
		GlobalResponseHeadersRemove: []string{},
	}

	assert.False(t, v.GlobalResponseHeadersEnabled())

	// add headers
	v.GlobalResponseHeaders["a"] = "b"
	assert.True(t, v.GlobalResponseHeadersEnabled())
	v.GlobalResponseHeadersDisabled = true
	assert.False(t, v.GlobalResponseHeadersEnabled())

	// reset
	v.GlobalResponseHeaders = map[string]string{}
	v.GlobalResponseHeadersDisabled = false
	assert.False(t, v.GlobalResponseHeadersEnabled())

	// remove headers
	v.GlobalResponseHeadersRemove = []string{"a"}
	assert.True(t, v.GlobalResponseHeadersEnabled())
	v.GlobalResponseHeadersDisabled = true
	assert.False(t, v.GlobalResponseHeadersEnabled())
}

func TestVersionInfo_HasEndpointResHeader(t *testing.T) {
	v := apidef.VersionInfo{}

	assert.False(t, v.HasEndpointResHeader())
	v.UseExtendedPaths = true
	assert.False(t, v.HasEndpointResHeader())

	v.ExtendedPaths.TransformResponseHeader = make([]apidef.HeaderInjectionMeta, 2)
	assert.False(t, v.HasEndpointResHeader())

	v.ExtendedPaths.TransformResponseHeader[0].Disabled = true
	v.ExtendedPaths.TransformResponseHeader[0].AddHeaders = map[string]string{"a": "b"}
	assert.False(t, v.HasEndpointResHeader())

	v.ExtendedPaths.TransformResponseHeader[1].Disabled = false
	v.ExtendedPaths.TransformResponseHeader[1].DeleteHeaders = []string{"a"}
	assert.True(t, v.HasEndpointResHeader())
}
