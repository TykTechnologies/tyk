package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/justinas/alice"
	"github.com/satori/go.uuid"
)

func createRLSession() *SessionState {
	session := new(SessionState)
	// essentially non-throttled
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10
	session.AccessRights = map[string]AccessDefinition{"31445455": {APIName: "Tyk Auth Key Test", APIID: "31445455", Versions: []string{"default"}}}
	return session
}

func getRLOpenChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&RateLimitForAPI{BaseMiddleware: baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
	)...).Then(proxyHandler)
	return chain
}

func getGlobalRLAuthKeyChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitForAPI{BaseMiddleware: baseMid},
		&RateLimitAndQuotaCheck{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func TestRLOpen(t *testing.T) {
	spec := createSpecTest(t, openRLDefSmall)

	req := testReq(t, "GET", "/rl_test/", nil)

	DRLManager.CurrentTokenValue = 1
	DRLManager.RequestTokenValue = 1

	chain := getRLOpenChain(spec)
	for a := 0; a <= 10; a++ {
		recorder := httptest.NewRecorder()
		chain.ServeHTTP(recorder, req)
		if a < 3 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit kicked in too early, after only %v requests", a)
			}
		}

		if a > 7 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit did not activate, code was: %v", recorder.Code)
			}
		}
	}

	DRLManager.CurrentTokenValue = 0
	DRLManager.RequestTokenValue = 0
}

func TestRLClosed(t *testing.T) {
	spec := createSpecTest(t, closedRLDefSmall)

	req := testReq(t, "GET", "/rl_closed_test/", nil)

	session := createRLSession()
	customToken := uuid.NewV4().String()
	// AuthKey sessions are stored by {token}
	spec.SessionManager.UpdateSession(customToken, session, 60)
	req.Header.Set("authorization", "Bearer "+customToken)

	DRLManager.CurrentTokenValue = 1
	DRLManager.RequestTokenValue = 1

	chain := getGlobalRLAuthKeyChain(spec)
	for a := 0; a <= 10; a++ {
		recorder := httptest.NewRecorder()
		chain.ServeHTTP(recorder, req)
		if a < 3 {
			if recorder.Code != 200 {
				t.Fatalf("Rate limit kicked in too early, after only %v requests", a)
			}
		}

		if a > 7 {
			if recorder.Code != 429 {
				t.Fatalf("Rate limit did not activate, code was: %v", recorder.Code)
			}
		}
	}

	DRLManager.CurrentTokenValue = 0
	DRLManager.RequestTokenValue = 0
}

const openRLDefSmall = `{
	"api_id": "313232",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/rl_test/",
		"target_url": "` + testHttpAny + `"
	},
	"global_rate_limit": {
		"rate": 3,
		"per": 1
	}
}`

const closedRLDefSmall = `{
	"api_id": "31445455",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/rl_closed_test/",
		"target_url": "` + testHttpAny + `"
	},
	"global_rate_limit": {
		"rate": 3,
		"per": 1
	}
}`
