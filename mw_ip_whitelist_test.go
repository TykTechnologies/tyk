package main

import (
	"net/http/httptest"
	"testing"
)

func TestIPMiddlewarePass(t *testing.T) {
	spec := buildAPI(func(spec *APISpec) {
		spec.EnableIpWhiteListing = true
		spec.AllowedIPs = []string{"127.0.0.1", "127.0.0.1/24"}
	})[0]

	for ti, tc := range []struct {
		remote, forwarded string
		wantCode          int
	}{
		{"127.0.0.1:80", "", 200},         // remote exact match
		{"127.0.0.2:80", "", 200},         // remote CIDR match
		{"10.0.0.1:80", "", 403},          // no match
		{"10.0.0.1:80", "127.0.0.1", 200}, // forwarded exact match
		{"10.0.0.1:80", "127.0.0.2", 200}, // forwarded CIDR match
	} {
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
