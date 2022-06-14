package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var testWhiteListIPData = []struct {
	remote, forwarded string
	wantCode          int
}{
	{"127.0.0.1:80", "", http.StatusOK},         // remote exact match
	{"127.0.0.2:80", "", http.StatusOK},         // remote CIDR match
	{"10.0.0.1:80", "", http.StatusForbidden},   // no match
	{"10.0.0.1:80", "127.0.0.1", http.StatusOK}, // forwarded exact match
	{"10.0.0.1:80", "127.0.0.2", http.StatusOK}, // forwarded CIDR match
}

func testPrepareIPMiddlewarePass() *APISpec {
	return BuildAPI(func(spec *APISpec) {
		spec.EnableIpWhiteListing = true
		spec.AllowedIPs = []string{"127.0.0.1", "127.0.0.1/24"}
	})[0]
}

func TestIPMiddlewarePass(t *testing.T) {
	spec := testPrepareIPMiddlewarePass()

	for ti, tc := range testWhiteListIPData {
		rec := httptest.NewRecorder()
		req := testReq(t, "GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}

		mw := &IPWhiteListMiddleware{}
		mw.Spec = spec
		_, code := mw.ProcessRequest(rec, req, nil)

		if code != tc.wantCode {
			t.Errorf("[%d] Response code %d should be %d\n%q %q", ti,
				code, tc.wantCode, tc.remote, tc.forwarded)
		}
	}
}

func BenchmarkIPMiddlewarePass(b *testing.B) {
	b.ReportAllocs()

	spec := testPrepareIPMiddlewarePass()
	mw := &IPWhiteListMiddleware{}
	mw.Spec = spec

	rec := httptest.NewRecorder()
	for i := 0; i < b.N; i++ {
		for ti, tc := range testWhiteListIPData {
			req := testReq(b, "GET", "/", nil)
			req.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}

			_, code := mw.ProcessRequest(rec, req, nil)

			if code != tc.wantCode {
				b.Errorf("[%d] Response code %d should be %d\n%q %q", ti,
					code, tc.wantCode, tc.remote, tc.forwarded)
			}
		}
	}
}
