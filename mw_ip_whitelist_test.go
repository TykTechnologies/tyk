package main

import (
	"net/http/httptest"
	"testing"
)

const ipMiddlewareTestDefinitionEnabledFail = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {"v1": { "name": "v1" }}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	},
	"enable_ip_whitelisting": true,
	"allowed_ips": ["12.12.12.12"]
}`

const ipMiddlewareTestDefinitionEnabledPass = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {"v1": { "name": "v1" }}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	},
	"enable_ip_whitelisting": true,
	"allowed_ips": ["127.0.0.1", "127.0.0.1/24"]
}`

const ipMiddlewareTestDefinitionDisabled = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {"v1": { "name": "v1" }}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

const ipMiddlewareTestDefinitionMissing = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {"v1": { "name": "v1" }}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestIpMiddlewareIPFail(t *testing.T) {
	spec := createSpecTest(t, ipMiddlewareTestDefinitionEnabledFail)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234wer", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:80"
	req.Header.Set("authorization", "1234wer")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Invalid response code, should be 403:  \n", recorder.Code, recorder.Body)
	}
}

func TestIPMiddlewarePass(t *testing.T) {
	spec := createSpecTest(t, ipMiddlewareTestDefinitionEnabledPass)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", session, 60)
	for _, tc := range []struct {
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
		req.Header.Set("authorization", "gfgg1234")
		if tc.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tc.forwarded)
		}

		chain := getChain(spec)
		chain.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("Response code %d should be %d\n%q %q\n%s",
				rec.Code, tc.wantCode, tc.remote, tc.forwarded, rec.Body.String())
		}
	}
}

func TestIpMiddlewareIPMissing(t *testing.T) {
	spec := createSpecTest(t, ipMiddlewareTestDefinitionMissing)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234rtyrty", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "1234rtyrty")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}

func TestIpMiddlewareIPDisabled(t *testing.T) {
	spec := createSpecTest(t, ipMiddlewareTestDefinitionDisabled)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234iuouio", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "1234iuouio")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}
