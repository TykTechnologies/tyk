package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/header"
)

var testWhiteListIPData = []struct {
	remote, forwarded, xRealIP string
	wantCode                   int
}{
	{"127.0.0.1:80", "", "", http.StatusOK},          // remote exact match
	{"127.0.0.2:80", "", "", http.StatusOK},          // remote CIDR match
	{"10.0.0.1:80", "", "", http.StatusForbidden},    // no match
	{"10.0.0.1:80", "127.0.0.1", "", http.StatusOK},  // forwarded exact match
	{"10.0.0.1:80", "127.0.0.2", "", http.StatusOK},  // forwarded CIDR match
	{"10.0.0.1:80", "", "bob", http.StatusForbidden}, // no match
}

func testPrepareIPMiddlewarePass() *APISpec {
	return BuildAPI(func(spec *APISpec) {
		spec.EnableIpWhiteListing = true
		spec.AllowedIPs = []string{"127.0.0.1", "127.0.0.1/24", "bob"}
	})[0]
}

func TestIPMiddlewarePass(t *testing.T) {
	spec := testPrepareIPMiddlewarePass()

	for ti, tc := range testWhiteListIPData {
		rec := httptest.NewRecorder()
		req := TestReq(t, "GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}

		if tc.xRealIP != "" {
			req.Header.Set(header.XRealIP, tc.xRealIP)
		}

		mw := &IPWhiteListMiddleware{BaseMiddleware: &BaseMiddleware{}}
		mw.Spec = spec
		_, code := mw.ProcessRequest(rec, req, nil)

		if code != tc.wantCode {
			t.Errorf("[%d] Response code %d should be %d\n%q %q %q", ti,
				code, tc.wantCode, tc.remote, tc.forwarded, tc.xRealIP)
		}
	}
}

func BenchmarkIPMiddlewarePass(b *testing.B) {
	b.ReportAllocs()

	spec := testPrepareIPMiddlewarePass()
	mw := &IPWhiteListMiddleware{BaseMiddleware: &BaseMiddleware{}}
	mw.Spec = spec

	rec := httptest.NewRecorder()
	for i := 0; i < b.N; i++ {
		for ti, tc := range testWhiteListIPData {
			req := TestReq(b, "GET", "/", nil)
			req.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}

			if tc.xRealIP != "" {
				req.Header.Set(header.XRealIP, tc.xRealIP)
			}

			_, code := mw.ProcessRequest(rec, req, nil)

			if code != tc.wantCode {
				b.Errorf("[%d] Response code %d should be %d\n%q %q %q", ti,
					code, tc.wantCode, tc.remote, tc.forwarded, tc.xRealIP)
			}
		}
	}
}
