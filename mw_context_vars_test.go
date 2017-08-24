package main

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

const contextVarsMiddlewareDefinition = `{
	"api_id": "1",
	"org_id": "default",
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
				"global_headers":{
					"X-Static": "foo",
					"X-Request-ID":"$tyk_context.request_id",
					"X-Path": "$tyk_context.path",
					"X-Remote-Addr": "$tyk_context.remote_addr"
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	},
	"enable_context_vars": true
}`

func TestContextVarsMiddleware(t *testing.T) {
	spec := createSpecTest(t, contextVarsMiddlewareDefinition)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234wer", session, 60)
	uri := "/test/this/path"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req := testReq(t, method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.1:80"
	req.Header.Set("authorization", "1234wer")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Fatal("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}

	if req.Header.Get("X-Static") == "" {
		t.Fatal("Sanity check failed: could not find static const in header")
	}

	if req.Header.Get("X-Path") == "" {
		t.Fatal("Could not find Path in header")
	}

	if req.Header.Get("X-Remote-Addr") == "" {
		t.Fatal("Could not find Remote-Addr in header")
	}

	if req.Header.Get("X-Request-ID") == "" {
		t.Fatal("Could not find Correlation ID in header")
	}

}
