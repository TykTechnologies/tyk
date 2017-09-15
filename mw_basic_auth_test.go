package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

const basicAuthDef = `{
	"api_id": "1",
	"org_id": "default",
	"use_basic_auth": true,
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `"
	}
}`

func createBasicAuthSession() *SessionState {
	session := new(SessionState)
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 1
	session.QuotaMax = -1
	session.BasicAuthData.Password = "TEST"
	return session
}

func getBasicAuthChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(testHttpAny)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := &BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&BasicAuthKeyIsValid{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func TestBasicAuthSession(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code, should have gone through!: \n", recorder.Code)
	}
}

func TestBasicAuthBadFormatting(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{username, password}, "-")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthBadData(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := "ldhflsdflksjfdlksjflksdjlskdjflkjsfd:::jhdsgfkjahsgdkhasdgjhgasdjhads:::aksdakjsdh:adskasdkjhasdkjhad-asdads"
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthBadOverFormatting(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	username := "4321"
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{username, password, "banana"}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 400 {
		t.Error("Request didn't return 400 code!: \n", recorder.Code)
	}
}

func TestBasicAuthWrongUser(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	password := "TEST"
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{"1234", password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("Request should have returned WWW-Authenticate header!: \n")
	}
}

func TestBasicMissingHeader(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}
}

func TestBasicAuthWrongPassword(t *testing.T) {
	spec := createSpecTest(t, basicAuthDef)
	session := createBasicAuthSession()
	username := "4321"

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{username, "WRONGPASSTEST"}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed and returned non-200 code!: \n", recorder.Code)
	}

	if recorder.Code != 401 {
		t.Error("Request should have returned 401 code!: \n", recorder.Code)
	}

	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Error("Request should have returned WWW-Authenticate header!: \n")
	}
}
