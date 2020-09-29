package gateway

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/test"
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

func testPrepareVirtualEndpoint(js string, method string, path string, proxyOnError bool) {
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"

		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   "blob",
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 path,
			Method:               method,
			ProxyOnError:         proxyOnError,
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

		// Address https://github.com/TykTechnologies/tyk/v3/issues/1356
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

	testPrepareVirtualEndpoint(virtTestJS, "GET", "/virt", true)

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

	testPrepareVirtualEndpoint("abc", "GET", "/abc", false)

	ts.Run(t, test.TestCase{
		Path: "/abc",
		Code: http.StatusInternalServerError,
	})
}

func BenchmarkVirtualEndpoint(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	testPrepareVirtualEndpoint(virtTestJS, "GET", "/virt", true)

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
