package main

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
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

func TestVirtualEndpoint(t *testing.T) {
	config.Global.ListenAddress = "127.0.0.1"

	ln, _ := generateListener(0)
	baseURL := "http://" + ln.Addr().String()
	listen(ln, nil, nil)
	defer func() {
		config.Global.ListenAddress = ""
		ln.Close()
	}()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"

		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "testVirtData",
			FunctionSourceType:   "blob",
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(virtTestJS)),
			Path:                 "/virt",
			Method:               "GET",
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

	resp, err := http.Get(baseURL + "/virt")
	if err != nil {
		t.Fatal(err)
	}

	if want := 202; resp.StatusCode != 202 {
		t.Fatalf("wanted code to be %d, got %d", want, resp.StatusCode)
	}

	wantBody := "foobar"
	gotBody, _ := ioutil.ReadAll(resp.Body)

	if wantBody != string(gotBody) {
		t.Fatalf("wanted body to be %q, got %q", wantBody, string(gotBody))
	}
	if want, got := "x", resp.Header.Get("data-foo"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	if want, got := "3", resp.Header.Get("data-bar-y"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}
