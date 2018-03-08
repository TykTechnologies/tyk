package main

import (
	"encoding/json"
	"github.com/TykTechnologies/tyk/apidef"
	"testing"

	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestResponseHeaderInjection(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

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
				}
			]`), &v.ExtendedPaths.TransformResponseHeader)
		})
		spec.ResponseProcessors = []apidef.ResponseProcessor{{Name: "header_injector"}}
	})

	session := createStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{"test": {APIID: "test", Versions: []string{"v1"}}}

	addHeaders := make(map[string]string)
	deleteHeaders := make(map[string]string)
	addHeaders["X-Test"] = "test"
	deleteHeaders["X-Tyk-Mock"] = "1"

	ts.Run(t, []test.TestCase{
		// Create base auth based key
		{Method: "GET", Path: "/test-with-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
		{Method: "GET", Path: "/test-no-slash", HeadersMatch: addHeaders, HeadersNotMatch: deleteHeaders},
	}...)
}
