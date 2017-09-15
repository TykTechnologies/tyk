// +build coprocess
// +build !python

package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

/* Value Extractor tests, using "header" source */

func TestValueExtractorHeaderSource(t *testing.T) {
	spec := createSpecTest(t, idExtractorCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	baseMid := BaseMiddleware{spec, proxy}

	newExtractor(spec, baseMid)

	extractor := baseMid.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

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

	sessionID, returnOverrides := extractor.ExtractAndCheck(req)
	_, _ = sessionID, returnOverrides
}

/* Value Extractor tests, using "form" source */

func TestValueExtractorFormSource(t *testing.T) {
	spec := createSpecTest(t, valueExtractorFormSource)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	baseMid := BaseMiddleware{spec, proxy}

	newExtractor(spec, baseMid)

	extractor := baseMid.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	session := createBasicAuthSession()
	username := "4321"
	password := "TEST"

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	authValue := "abc"

	recorder := httptest.NewRecorder()
	req := testReq(t, "POST", "/", nil)
	req.Form = url.Values{}
	req.Form.Add("auth", authValue)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	sessionID, _ := extractor.ExtractAndCheck(req)
	expectedSessionID := computeSessionID([]byte(authValue), baseMid)

	if sessionID != expectedSessionID {
		t.Fatal("Value Extractor output (using form source) doesn't match the computed session ID.")
	}
}

func TestValueExtractorHeaderSourceValidation(t *testing.T) {
	spec := createSpecTest(t, idExtractorCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	baseMid := BaseMiddleware{spec, proxy}

	newExtractor(spec, baseMid)

	extractor := baseMid.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	session := createBasicAuthSession()
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	// req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	_, returnOverrides := extractor.ExtractAndCheck(req)

	if returnOverrides.ResponseCode != 400 && returnOverrides.ResponseError != "Authorization field missing" {
		t.Fatal("ValueExtractor should return an error when the header is missing.")
	}
}

/* Regex Extractor tests, using "header" source */

func TestRegexExtractorHeaderSource(t *testing.T) {
	spec := createSpecTest(t, regexExtractorDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	baseMid := BaseMiddleware{spec, proxy}

	newExtractor(spec, baseMid)

	extractor := baseMid.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	session := createBasicAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", session, 60)

	fullHeaderValue := "token-12345"
	matchedHeaderValue := []byte("12345")

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("Authorization", fullHeaderValue)

	chain := getBasicAuthChain(spec)
	chain.ServeHTTP(recorder, req)

	sessionID, _ := extractor.ExtractAndCheck(req)
	expectedSessionID := computeSessionID(matchedHeaderValue, baseMid)

	if sessionID != expectedSessionID {
		t.Fatal("Regex Extractor output doesn't match the computed session ID.")
	}

}

func computeSessionID(input []byte, baseMid BaseMiddleware) (sessionID string) {
	tokenID := fmt.Sprintf("%x", md5.Sum(input))
	return baseMid.Spec.OrgID + tokenID
}

const idExtractorCoProcessDef = `{
	"api_id": "1",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"event_handlers": {
		"events": {"AuthFailure": [{
			"handler_name":"cp_dynamic_handler",
			"handler_meta": {
				"name": "my_handler"
			}
		}]}
	},
	"custom_middleware": {
		"pre": [{
			"name": "MyPreMiddleware"
		}],
		"id_extractor": {
			"extract_from": "header",
			"extract_with": "value",
			"extractor_config": {
				"header_name": "Authorization"
			}
		},
		"driver": "grpc"
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://httpbin.org"
	}
}`

const valueExtractorFormSource = `{
	"api_id": "1",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"event_handlers": {
		"events": {"AuthFailure": [{
			"handler_name":"cp_dynamic_handler",
			"handler_meta": {
				"name": "my_handler"
			}
		}]}
	},
	"custom_middleware": {
		"pre": [{
			"name": "MyPreMiddleware"
		}],
		"id_extractor": {
			"extract_from": "form",
			"extract_with": "value",
			"extractor_config": {
				"param_name": "auth"
			}
		},
		"driver": "grpc"
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://httpbin.org"
	}
}`

const regexExtractorDef = `{
	"api_id": "1",
	"org_id": "default",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"event_handlers": {
		"events": {"AuthFailure": [{
			"handler_name":"cp_dynamic_handler",
			"handler_meta": {
				"name": "my_handler"
			}
		}]}
	},
	"custom_middleware": {
		"id_extractor": {
			"extract_from": "header",
			"extract_with": "regex",
			"extractor_config": {
				"header_name": "Authorization",
				"regex_expression": "[^\\\\-]+",
				"regex_match_index": 1
			}
		},
		"driver": "grpc"
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "http://httpbin.org"
	}
}`
