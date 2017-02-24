package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

func createAuthKeyAuthSession() SessionState {
	var session SessionState
	// essentially non-throttled
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.Expires = 0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10

	session.AccessRights = map[string]AccessDefinition{"31": {APIName: "Tyk Auth Key Test", APIID: "31", Versions: []string{"default"}}}

	return session
}

func getAuthKeyChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

func TestBearerTokenAuthKeySession(t *testing.T) {
	spec := createSpecTest(t, authKeyDef)
	session := createAuthKeyAuthSession()
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth_key_test/", nil)

	if err != nil {
		t.Fatal("Problem creating new request object.", err)
	}

	req.Header.Add("authorization", "Bearer "+customToken)

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}
}

const authKeyDef = `{
	"name": "Tyk Auth Key Test",
	"api_id": "31",
	"org_id": "default",
	"use_keyless": false,
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default",
				"use_extended_paths": true,
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": [],
					"white_list": [],
					"black_list": []
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": true
	}
}`

func TestMultiAuthBackwardsCompatibleSession(t *testing.T) {
	spec := createSpecTest(t, multiAuthBackwardsCompatible)
	session := createAuthKeyAuthSession()
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), strings.NewReader(""))

	if err != nil {
		t.Fatal("Problem creating new request object.", err)
	}

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}
}

const multiAuthBackwardsCompatible = `{
	"name": "Tyk Auth Key Test",
	"api_id": "31",
	"org_id": "default",
	"use_keyless": false,
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "token",
		"use_param": true
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default",
				"use_extended_paths": true,
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": [],
					"white_list": [],
					"black_list": []
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": true
	}
}`

func TestMultiAuthSession(t *testing.T) {
	spec := createSpecTest(t, multiAuthDef)
	session := createAuthKeyAuthSession()
	customToken := "54321111"
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60)

	var req *http.Request
	var err error

	// Set the url param
	recorder := httptest.NewRecorder()
	if req, err = http.NewRequest("GET", fmt.Sprintf("/auth_key_test/?token=%s", customToken), strings.NewReader("")); err != nil {
		t.Fatal("Problem creating new request object.", err)
	}

	chain := getAuthKeyChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("First request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}

	// Set the header
	recorder = httptest.NewRecorder()
	if req, err = http.NewRequest("GET", "/auth_key_test/?token=", strings.NewReader("")); err != nil {
		t.Fatal("Problem creating new request object.", err)
	}
	req.Header.Add("authorization", customToken)

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Second request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}

	// Set the cookie
	recorder = httptest.NewRecorder()
	if req, err = http.NewRequest("GET", "/auth_key_test/?token=", strings.NewReader("")); err != nil {
		t.Fatal("Problem creating new request object.", err)
	}
	req.AddCookie(&http.Cookie{Name: "oreo", Value: customToken})

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Third request failed with non-200 code, should have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}

	// No header, param or cookie
	recorder = httptest.NewRecorder()
	if req, err = http.NewRequest("GET", "/auth_key_test/", strings.NewReader("")); err != nil {
		t.Fatal("Problem creating new request object.", err)
	}

	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request returned 200 code, should NOT have gone through!: \n", recorder.Code)
		t.Error(ioutil.ReadAll(recorder.Body))
	}
}

const multiAuthDef = `{
	"name": "Tyk Auth Key Test",
	"api_id": "31",
	"org_id": "default",
	"use_keyless": false,
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization",
		"param_name": "token",
		"cookie_name": "oreo"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default",
				"use_extended_paths": true,
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": [],
					"white_list": [],
					"black_list": []
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/auth_key_test/",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": true
	}
}`
