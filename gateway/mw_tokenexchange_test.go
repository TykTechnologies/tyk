
//go:build !race || unstable
// +build !race unstable

package gateway

import (
		"testing"
		"net/http/httptest"

		"github.com/TykTechnologies/tyk/header"
)

func TestJWTMiddlewarePass(t *testing.T) {
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

// func TestProcessRequest(t *testing.T) {
 

// 	k.Spec = &apidef.APIDefinition {
// 		jwt: OAuthTokenExchangeMW{
// 			Enable: true,
// 			ClientID: "gw_client_id",
// 			ClientSecret: "gw_client_secret", 
// 			GrantType: "client_credentials",
// 			Scopes: "read write",
// 		},
// 	}


//     // create a mock request
//     r, err := http.NewRequest("GET", "/myapi", nil)
//     if err != nil {
//         t.Fatal(err)
//     }

//     // create a mock response writer
//     w := httptest.NewRecorder()

//     // call the handler function
//     err, status := k.ProcessRequest(w, r, nil)

//     // assert the expected results
//     assert.Nil(t, err) // no error should be returned
//     assert.Equal(t, http.StatusOK, status) // status should be 200 OK
//     // check the response body, headers, etc. as needed
// }


