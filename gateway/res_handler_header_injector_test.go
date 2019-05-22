package gateway

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func testPrepareResponseHeaderInjection() {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.OrgID = "default"
		updateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			json.Unmarshal([]byte(`[
				{
					"delete_headers": ["X-Tyk-Mock"],
					"add_headers": {"X-Test": "test"},
					"path": "/test-with-slash",
					"method": "GET",
					"act_on": false
				},
				{
					"delete_headers": ["X-Tyk-Mock"],
					"add_headers": {"X-Test": "test"},
					"path": "test-no-slash",
					"method": "GET",
					"act_on": false
				},
				{
					"delete_headers": ["X-Tyk-Mock"],
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
	})
}

func TestResponseHeaderInjection(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	testPrepareResponseHeaderInjection()

	addHeaders := map[string]string{"X-Test": "test"}
	deleteHeaders := map[string]string{"X-Tyk-Mock": "1"}
	userAgent := fmt.Sprintf("\"User-Agent\":\"Tyk/%v\"", VERSION)

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
		{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"Url":"/newpath"`},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"X-I-Am":"Request"`},
		{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: userAgent},
	}...)
}

func BenchmarkResponseHeaderInjection(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	testPrepareResponseHeaderInjection()

	addHeaders := map[string]string{"X-Test": "test"}
	deleteHeaders := map[string]string{"X-Tyk-Mock": "1"}
	userAgent := fmt.Sprintf("\"User-Agent\":\"Tyk/%v\"", VERSION)

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			// Create base auth based key
			{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"Url":"/newpath"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: `"X-I-Am":"Request"`},
			{Method: "GET", Path: "/rewrite-test", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders, BodyMatch: userAgent},
		}...)
	}
}
