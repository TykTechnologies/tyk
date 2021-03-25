package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

const virtTestJS = `
function testVirtData(request, session, config) {
	var resp = {
		Body: "foobar",
		Headers: {
			"data-foo": config.config_data.foo,
			"data-bar-y": config.config_data.bar.y.toString()
		},
		Code: 202
	}
	return TykJsResponse(resp, session.meta_data)
}
`

func testPrepareVirtualEndpoint(js string, method string, path string, proxyOnError bool, keyless bool) {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "test"
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = keyless
		spec.Auth = apidef.AuthConfig{AuthHeaderName: "Authorization"}
		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   "blob",
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 path,
			Method:               method,
			ProxyOnError:         proxyOnError,
		}
		if !keyless {
			virtualMeta.UseSession = true
		}
		v := spec.VersionData.Versions["v1"]
		v.UseExtendedPaths = true
		v.ExtendedPaths = apidef.ExtendedPathsSet{
			Virtual: []apidef.VirtualMeta{virtualMeta},
		}
		spec.VersionData.Versions["v1"] = v

		spec.ConfigData = map[string]interface{}{
			"foo": "x",
			"bar": map[string]interface{}{"y": 3},
		}

		// Address https://github.com/TykTechnologies/tyk/issues/1356
		// VP should work with cache enabled
		spec.CacheOptions = apidef.CacheOptions{
			EnableCache:          true,
			CacheTimeout:         60,
			CacheAllSafeRequests: true,
		}
	})
}

func TestVirtualEndpoint(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	testPrepareVirtualEndpoint(virtTestJS, "GET", "/virt", true, true)

	ts.Run(t, test.TestCase{
		Path:      "/virt",
		Code:      202,
		BodyMatch: "foobar",
		HeadersMatch: map[string]string{
			"data-foo":   "x",
			"data-bar-y": "3",
		},
	})
}

func TestVirtualEndpoint500(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	testPrepareVirtualEndpoint("abc", "GET", "/abc", false, true)

	ts.Run(t, test.TestCase{
		Path: "/abc",
		Code: http.StatusInternalServerError,
	})
}

func TestVirtualEndpointSessionMetadata(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
		s.MetaData = map[string]interface{}{
			"tyk_developer_id":       "5f11cc1ba4b16a176b4a6735",
			"tyk_key_request_fields": map[string]string{"key": "value"},
			"tyk_user_fields":        map[string]string{"key": "value"},
		}
	})

	testPrepareVirtualEndpoint(virtTestJS, "GET", "/abc", false, false)

	ts.Run(t, test.TestCase{
		Path:    "/abc",
		Headers: map[string]string{"Authorization": key},
		Code:    http.StatusAccepted,
	})
}

func BenchmarkVirtualEndpoint(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	testPrepareVirtualEndpoint(virtTestJS, "GET", "/virt", true, true)

	for i := 0; i < b.N; i++ {
		ts.Run(b, test.TestCase{
			Path:      "/virt",
			Code:      202,
			BodyMatch: "foobar",
			HeadersMatch: map[string]string{
				"data-foo":   "x",
				"data-bar-y": "3",
			},
		})
	}
}
