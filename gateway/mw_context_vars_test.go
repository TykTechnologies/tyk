package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/test"
)

func testPrepareContextVarsMiddleware() {
	BuildAndLoadAPI(func(spec *APISpec) {
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
	ts := StartTest()
	defer ts.Close()

	testPrepareContextVarsMiddleware()

	ts.Run(t, []test.TestCase{
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Remote-Addr":"127.0.0.1"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Path":"/test/path"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Static":"foo"`},
		{Path: "/test/path", Code: 200, BodyMatch: `"X-Request-Id":"`},
	}...)
}

func BenchmarkContextVarsMiddleware(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest()
	defer ts.Close()

	testPrepareContextVarsMiddleware()

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Remote-Addr":"127.0.0.1"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Path":"/test/path"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Static":"foo"`},
			{Path: "/test/path", Code: 200, BodyMatch: `"X-Request-Id":"`},
		}...)
	}
}

type testContextVarsData struct {
	Method                string
	URL                   string
	Data                  string
	ExpectedCtxDataObject map[string]interface{}
	Header                http.Header
}

func testPrepareTestContextVarsMiddleware() map[string]testContextVarsData {
	return map[string]testContextVarsData{
		"GET with query string": {
			Method: http.MethodGet,
			URL:    "http://abc.com/aaa/bbb/111/222?x=123&y=test",
			Header: http.Header{
				"x-header-a": {"A"},
				"x-header-b": {"B"},
				"x-header-c": {"C"},
			},
			ExpectedCtxDataObject: map[string]interface{}{
				"remote_addr": "192.0.2.1",
				"request_data": url.Values{
					"x": {"123"},
					"y": {"test"},
				},
				"headers": map[string][]string{
					"x-header-a": {"A"},
					"x-header-b": {"B"},
					"x-header-c": {"C"},
				},
				"headers_x_header_a": "A",
				"headers_x_header_b": "B",
				"headers_x_header_c": "C",
				"headers_Host":       "abc.com",
				"path_parts":         []string{"", "aaa", "bbb", "111", "222"},
				"path":               "/aaa/bbb/111/222",
			},
		},
		"POST with query string and encoded form data": {
			Method: http.MethodPost,
			URL:    "http://abc.com/aaa/bbb/111/222?x=123&y=test",
			Data:   "i=1&j=2&str=abc",
			Header: http.Header{
				"Content-Type": {"application/x-www-form-urlencoded"},
				"x-header-a":   {"A"},
				"x-header-b":   {"B"},
				"x-header-c":   {"C"},
			},
			ExpectedCtxDataObject: map[string]interface{}{
				"remote_addr": "192.0.2.1",
				"request_data": url.Values{
					"x":   {"123"},
					"y":   {"test"},
					"i":   {"1"},
					"j":   {"2"},
					"str": {"abc"},
				},
				"headers": map[string][]string{
					"x-header-a":   {"A"},
					"x-header-b":   {"B"},
					"x-header-c":   {"C"},
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
				"headers_x_header_a":   "A",
				"headers_x_header_b":   "B",
				"headers_x_header_c":   "C",
				"headers_Content_Type": "application/x-www-form-urlencoded",
				"headers_Host":         "abc.com",
				"path_parts":           []string{"", "aaa", "bbb", "111", "222"},
				"path":                 "/aaa/bbb/111/222",
			},
		},
		"POST with query string and encoded form data and cookies": {
			Method: http.MethodPost,
			URL:    "http://abc.com/aaa/bbb/111/222?x=123&y=test",
			Data:   "i=1&j=2&str=abc",
			Header: http.Header{
				"Content-Type": {"application/x-www-form-urlencoded"},
				"Cookie":       {"c-1=cookie1;c-2=cookie2"},
				"x-header-a":   {"A"},
				"x-header-b":   {"B"},
				"x-header-c":   {"C"},
			},
			ExpectedCtxDataObject: map[string]interface{}{
				"remote_addr": "192.0.2.1",
				"request_data": url.Values{
					"x":   {"123"},
					"y":   {"test"},
					"i":   {"1"},
					"j":   {"2"},
					"str": {"abc"},
				},
				"headers": map[string][]string{
					"x-header-a":   {"A"},
					"x-header-b":   {"B"},
					"x-header-c":   {"C"},
					"Content-Type": {"application/x-www-form-urlencoded"},
					"Cookie":       {"c-1=cookie1;c-2=cookie2"},
				},
				"headers_x_header_a":   "A",
				"headers_x_header_b":   "B",
				"headers_x_header_c":   "C",
				"headers_Content_Type": "application/x-www-form-urlencoded",
				"headers_Cookie":       "c-1=cookie1;c-2=cookie2",
				"headers_Host":         "abc.com",
				"cookies_c_1":          "cookie1",
				"cookies_c_2":          "cookie2",
				"path_parts":           []string{"", "aaa", "bbb", "111", "222"},
				"path":                 "/aaa/bbb/111/222",
			},
		},
	}
}

func TestContextVarsMiddlewareProcessRequest(t *testing.T) {
	mw := &MiddlewareContextVars{}

	tests := testPrepareTestContextVarsMiddleware()

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var bodyReader io.Reader
			if test.Data != "" {
				bodyReader = strings.NewReader(test.Data)
			}
			req := httptest.NewRequest(test.Method, test.URL, bodyReader)
			req.Header = test.Header
			err, code := mw.ProcessRequest(nil, req, nil)
			if err != nil {
				t.Error(err)
			}
			if code != http.StatusOK {
				t.Errorf("Wrong response code: %d Eexpected 200.", code)
			}

			ctxDataObject := ctxGetData(req)

			// check request_id
			if _, ok := ctxDataObject["request_id"].(string); !ok {
				t.Error("Missing 'request_id' field")
			}

			// delete request_if to do DeepEqual
			delete(ctxDataObject, "request_id")

			if !reflect.DeepEqual(ctxDataObject, test.ExpectedCtxDataObject) {
				t.Errorf("Expected: %v\n Got: %v\n", test.ExpectedCtxDataObject, ctxDataObject)
			}
		})
	}
}

func BenchmarkContextVarsMiddlewareProcessRequest(b *testing.B) {
	mw := &MiddlewareContextVars{}
	tests := testPrepareTestContextVarsMiddleware()
	var err error
	var code int
	for name, test := range tests {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var bodyReader io.Reader
				if test.Data != "" {
					bodyReader = strings.NewReader(test.Data)
				}
				req := httptest.NewRequest(test.Method, test.URL, bodyReader)
				req.Header = test.Header
				err, code = mw.ProcessRequest(nil, req, nil)
				if err != nil {
					b.Error(err)
				}
				if code != http.StatusOK {
					b.Errorf("Wrong response code: %d Eexpected 200.", code)
				}
			}
		})
	}
}
