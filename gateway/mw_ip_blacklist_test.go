package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var testBlackListIPData = []struct {
	remote, forwarded string
	wantCode          int
}{
	{"127.0.0.1:80", "", http.StatusForbidden},         // remote exact match
	{"127.0.0.2:80", "", http.StatusForbidden},         // remote CIDR match
	{"10.0.0.1:80", "", http.StatusOK},                 // no match
	{"10.0.0.1:80", "127.0.0.1", http.StatusForbidden}, // forwarded exact match
	{"10.0.0.1:80", "127.0.0.2", http.StatusForbidden}, // forwarded CIDR match
}

func testPrepareIPBlacklistMiddleware() *APISpec {
	return BuildAPI(func(spec *APISpec) {
		spec.EnableIpBlacklisting = true
		spec.BlacklistedIPs = []string{"127.0.0.1", "127.0.0.1/24"}
	})[0]
}

func TestIPBlacklistMiddleware(t *testing.T) {
	spec := testPrepareIPBlacklistMiddleware()

	for ti, tc := range testBlackListIPData {
		rec := httptest.NewRecorder()
		req := testReq(t, "GET", "/", nil)
		req.RemoteAddr = tc.remote
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}

		mw := &IPBlackListMiddleware{}
		mw.Spec = spec
		_, code := mw.ProcessRequest(rec, req, nil)

		if code != tc.wantCode {
			t.Errorf("[%d] Response code %d should be %d\n%q %q", ti,
				code, tc.wantCode, tc.remote, tc.forwarded)
		}
	}
}

func BenchmarkIPBlacklistMiddleware(b *testing.B) {
	b.ReportAllocs()

	spec := testPrepareIPBlacklistMiddleware()

	mw := &IPBlackListMiddleware{}
	mw.Spec = spec

	rec := httptest.NewRecorder()
	for i := 0; i < b.N; i++ {
		for ti, tc := range testBlackListIPData {
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
