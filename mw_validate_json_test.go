package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
)

var schema string = `{
    "title": "Person",
    "type": "object",
    "properties": {
        "firstName": {
            "type": "string"
        },
        "lastName": {
            "type": "string"
        },
        "age": {
            "description": "Age in years",
            "type": "integer",
            "minimum": 0
        }
    },
    "required": ["firstName", "lastName"]
}`

const validateJSONPathGatewaySetup = `{
	"api_id": "jsontest",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"default": {
				"name": "default",
				"use_extended_paths": true,
				"extended_paths": {
					"validate_json": [{
						"method": "POST",
						"path": "me",
						"validate_with": "ew0KICAgICJ0aXRsZSI6ICJQZXJzb24iLA0KICAgICJ0eXBlIjogIm9iamVjdCIsDQogICAgInByb3BlcnRpZXMiOiB7DQogICAgICAgICJmaXJzdE5hbWUiOiB7DQogICAgICAgICAgICAidHlwZSI6ICJzdHJpbmciDQogICAgICAgIH0sDQogICAgICAgICJsYXN0TmFtZSI6IHsNCiAgICAgICAgICAgICJ0eXBlIjogInN0cmluZyINCiAgICAgICAgfSwNCiAgICAgICAgImFnZSI6IHsNCiAgICAgICAgICAgICJkZXNjcmlwdGlvbiI6ICJBZ2UgaW4geWVhcnMiLA0KICAgICAgICAgICAgInR5cGUiOiAiaW50ZWdlciIsDQogICAgICAgICAgICAibWluaW11bSI6IDANCiAgICAgICAgfQ0KICAgIH0sDQogICAgInJlcXVpcmVkIjogWyJmaXJzdE5hbWUiLCAibGFzdE5hbWUiXQ0KfQ=="
					}]
				}
			}
		}
	},
	"proxy": {
		"listen_path": "/validate/",
		"target_url": "` + testHttpAny + `"
	}
}`

type out struct {
	Error string
	Code  int
}

func TestValidateSchema(t *testing.T) {
	want := []out{
		{"validation failed, server error", 400},
		{"payload validation failed: firstName: firstName is required: lastName: lastName is required", 400},
		{"payload validation failed: lastName: lastName is required", 400},
		{"", 200},
	}

	set := []string{
		``,
		`{}`,
		`{"firstName":"foo"}`,
		`{"firstName":"foo", "lastName":"foo"}`,
	}

	sch := base64.StdEncoding.EncodeToString([]byte(schema))
	for i, in := range set {
		e, code := validateJSONSchema(sch, in)
		if want[i].Error == "" {
			if e == nil && code != want[i].Code {
				t.Fatalf("Wanted nil error / %v, got %v / %v", want[i].Code, e, code)
			}
		} else {
			if e.Error() != want[i].Error || code != want[i].Code {
				t.Fatalf("Wanted: %v / %v, got %v / %v", want[i].Error, want[i].Code, e, code)
			}
		}

	}
}

func createJSONVersionedSession() *SessionState {
	session := new(SessionState)
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.AccessRights = map[string]AccessDefinition{"jsontest": {APIName: "Tyk Test API", APIID: "jsontest", Versions: []string{"default"}}}
	return session
}

func getJSONValidChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&MiddlewareContextVars{BaseMiddleware: baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
		&ValidateJSON{BaseMiddleware: baseMid},
		&TransformHeaders{baseMid},
	)...).Then(proxyHandler)
	return chain
}

func TestValidateSchemaMW(t *testing.T) {
	spec := createSpecTest(t, validateJSONPathGatewaySetup)
	recorder := httptest.NewRecorder()
	req := testReq(t, "POST", "/validate/me", `{"firstName":"foo", "lastName":"bar"}`)

	session := createJSONVersionedSession()
	spec.SessionManager.UpdateSession("986968696869688869696999", session, 60)
	req.Header.Set("Authorization", "986968696869688869696999")

	chain := getJSONValidChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Fatalf("Initial request failed with non-200 to: %v, code: %v (body: %v)", req.URL.String(), recorder.Code, recorder.Body)
	}
}

func TestValidateSchemaMWInvalid(t *testing.T) {
	spec := createSpecTest(t, validateJSONPathGatewaySetup)
	recorder := httptest.NewRecorder()
	req := testReq(t, "POST", "/validate/me", `{"firstName":"foo"}`)

	session := createJSONVersionedSession()
	spec.SessionManager.UpdateSession("986968696869688869696999", session, 60)
	req.Header.Set("Authorization", "986968696869688869696999")

	chain := getJSONValidChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 400 {
		t.Fatalf("Request code should have been 400: %v, code: %v (body: %v)", req.URL.String(), recorder.Code, recorder.Body)
	}

	want := "payload validation failed: lastName: lastName is required"
	if !strings.Contains(recorder.Body.String(), want) {
		t.Fatalf("Body shoul dhave contained error: %v, got: %v", want, recorder.Body.String())
	}
}
