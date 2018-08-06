package main

import (
	"encoding/base64"
	"testing"

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

func testPrepareVirtualEndpoint(js string, method string) {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"

		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   "blob",
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 "/virt",
			Method:               method,
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
	ts := newTykTestServer()
	defer ts.Close()

	testPrepareVirtualEndpoint(virtTestJS, "GET")

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

func BenchmarkVirtualEndpoint(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	testPrepareVirtualEndpoint(virtTestJS, "GET")

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
