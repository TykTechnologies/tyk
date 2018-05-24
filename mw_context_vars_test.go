package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func testPreparetContextVarsMiddleware() {
	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.EnableContextVars = true
		spec.VersionData.Versions = map[string]apidef.VersionInfo{
			"v1": {
				UseExtendedPaths: true,
				GlobalHeaders: map[string]string{
					"X-Static":      "foo",
					"X-Request-ID":  "$tyk_context.request_id",
					"X-Path":        "$tyk_context.path",
					"X-Remote-Addr": "$tyk_context.remote_addr",
				},
			},
		}
	})
}

func TestContextVarsMiddleware(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	testPreparetContextVarsMiddleware()

	ts.Run(t, []test.TestCase{
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Remote-Addr":"127.0.0.1"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Path":"/test/path"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Static":"foo"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Request-Id":"`},
	}...)
}

func BenchmarkContextVarsMiddleware(b *testing.B) {
	b.ReportAllocs()

	ts := newTykTestServer()
	defer ts.Close()

	testPreparetContextVarsMiddleware()

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Remote-Addr":"127.0.0.1"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Path":"/test/path"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Static":"foo"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Request-Id":"`},
		}...)
	}
}

func TestMiddlewareContextVars_ProcessRequest_cookies(t *testing.T) {

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	req.Header.Set("Cookie", "abc=123; def=456")

	err, code := (&MiddlewareContextVars{}).ProcessRequest(res, req, nil)
	if err != nil {
		t.Fatal(err)
	}

	if code != http.StatusOK {
		t.Fatal(errors.New("non 200 status code"))
	}

	ctx := ctxGetData(req)

	if ctx["cookies_abc"].(string) != "123" {
		t.Error("abc should be 123")
	}

	if ctx["cookies_def"].(string) != "456" {
		t.Error("def should be 456")
	}

	if ctx["cookies_ghi"] != nil {
		t.Error("ghi should be nil")
	}
}

func BenchmarkMiddlewareContextVars_ProcessRequest_cookies(b *testing.B) {
	b.ReportAllocs()

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	req.Header.Set("Cookie", "abc=123; def=456")

	for i := 0; i < b.N; i++ {
		err, code := (&MiddlewareContextVars{}).ProcessRequest(res, req, nil)
		if err != nil {
			b.Fatal(err)
		}
		if code != http.StatusOK {
			b.Fatal(errors.New("non 200 status code"))
		}
	}

}
