package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/user"
)

func createAuthKeyAuthSession() *user.SessionState {
	session := new(user.SessionState)
	// essentially non-throttled
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10
	session.AccessRights = map[string]user.AccessDefinition{"31": {APIName: "Tyk Auth Key Test", APIID: "31", Versions: []string{"default"}}}
	return session
}

func getAuthKeyChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&IPBlackListMiddleware{BaseMiddleware: baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func testPrepareAuthKeySession(tb testing.TB, apiDef string) (string, *APISpec) {
	spec := createSpecTest(tb, apiDef)
	session := createAuthKeyAuthSession()
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60, false)
	return customToken, spec
}

func TestBearerTokenAuthKeySession(t *testing.T) {
	customToken, spec := testPrepareAuthKeySession(t, authKeyDef)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/auth_key_test/", nil)

	req.Header.Set("authorization", "Bearer "+customToken)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

func BenchmarkBearerTokenAuthKeySession(b *testing.B) {
	b.ReportAllocs()

	customToken, spec := testPrepareAuthKeySession(b, authKeyDef)

	recorder := httptest.NewRecorder()
	req := testReq(b, "GET", "/auth_key_test/", nil)

	req.Header.Set("authorization", "Bearer "+customToken)

	chain := getAuthKeyChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
			b.Error(recorder.Body.String())
		}
	}
}

const authKeyDef = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestMultiAuthBackwardsCompatibleSession(t *testing.T) {
	customToken, spec := testPrepareAuthKeySession(t, multiAuthBackwardsCompatible)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

func BenchmarkMultiAuthBackwardsCompatibleSession(b *testing.B) {
	b.ReportAllocs()

	customToken, spec := testPrepareAuthKeySession(b, multiAuthBackwardsCompatible)

	recorder := httptest.NewRecorder()
	req := testReq(b, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)

	for i := 0; i < b.N; i++ {
		chain.ServeHTTP(recorder, req)
		if recorder.Code != 200 {
			b.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
			b.Error(recorder.Body.String())
		}
	}
}

const multiAuthBackwardsCompatible = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {
		"auth_header_name": "token",
		"use_param": true
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestMultiAuthSession(t *testing.T) {
	spec := createSpecTest(t, multiAuthDef)
	session := createAuthKeyAuthSession()
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60, false)

	// Set the url param
	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), nil)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("First request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// Set the header
	recorder = httptest.NewRecorder()
	req = testReq(t, "GET", "/auth_key_test/?token=", nil)
	req.Header.Set("authorization", customToken)

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Second request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// Set the cookie
	recorder = httptest.NewRecorder()
	req = testReq(t, "GET", "/auth_key_test/?token=", nil)
	req.AddCookie(&http.Cookie{Name: "oreo", Value: customToken})

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Third request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}

	// No header, param or cookie
	recorder = httptest.NewRecorder()
	req = testReq(t, "GET", "/auth_key_test/", nil)

	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request returned 200 code, should NOT have gone through!: \n", recorder.Code)
		t.Error(recorder.Body.String())
	}
}

const multiAuthDef = `{
	"api_id": "31",
	"org_id": "default",
	"auth": {
		"auth_header_name": "authorization",
		"param_name": "token",
		"cookie_name": "oreo"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `"
	}
}`
