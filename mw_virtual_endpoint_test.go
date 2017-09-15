package main

import (
	"io/ioutil"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const virtTestDef = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {
				"name": "v1",
				"use_extended_paths": true,
				"extended_paths": {
					"virtual": [{
						"response_function_name": "testVirtData",
						"function_source_type": "file",
						"function_source_uri": "middleware/testVirtData.js",
						"path": "/test-data",
						"method": "GET"
					}]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	},
	"config_data": {
		"foo": "x",
		"bar": {"y": 3}
	}
}`

const virtTestJS = `
function testVirtData(request, session, config) {
	var resp = {
		Body: request.Body + " added body",
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
	mwPath := filepath.Join("middleware", "testVirtData.js")
	if err := ioutil.WriteFile(mwPath, []byte(virtTestJS), 0644); err != nil {
		t.Fatal(err)
	}
	spec := createSpecTest(t, virtTestDef)
	defer os.Remove(mwPath)

	virt := &VirtualEndpoint{BaseMiddleware: BaseMiddleware{
		spec, nil,
	}}
	virt.Init()
	rec := httptest.NewRecorder()
	r := testReq(t, "GET", "/v1/test-data", "initial body")
	virt.ProcessRequest(rec, r, nil)
	if want := 202; rec.Code != 202 {
		t.Fatalf("wanted code to be %d, got %d", want, rec.Code)
	}
	wantBody := "initial body added body"
	gotBody := rec.Body.String()
	if wantBody != gotBody {
		t.Fatalf("wanted body to be %q, got %q", wantBody, gotBody)
	}
	if want, got := "x", rec.HeaderMap.Get("data-foo"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
	if want, got := "3", rec.HeaderMap.Get("data-bar-y"); got != want {
		t.Fatalf("wanted header to be %q, got %q", want, got)
	}
}
