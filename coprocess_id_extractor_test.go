// +build coprocess
// +build !python

package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"crypto/md5"
)

/* Value Extractor tests, using "header" source */

func TestValueExtractorHeaderSource(t *testing.T) {
	spec := MakeCoProcessSampleAPI(IdExtractorCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	tykMiddleware := &TykMiddleware{spec, proxy}

	newExtractor(spec, tykMiddleware)

	var thisExtractor IdExtractor
	thisExtractor = tykMiddleware.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	thisSession := createBasicAuthSession()
	username := "4321"
	password := "TEST"

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	to_encode := strings.Join([]string{username, password}, ":")
	encodedPass := base64.StdEncoding.EncodeToString([]byte(to_encode))
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(*spec)
	chain.ServeHTTP(recorder, req)

	var returnOverrides ReturnOverrides
	var SessionID string

	SessionID, returnOverrides = thisExtractor.ExtractAndCheck(req)

	fmt.Println("SessionID=", SessionID)
	fmt.Println("returnOverrides", returnOverrides)

}

func TestValueExtractorHeaderSourceValidation(t *testing.T) {
	spec := MakeCoProcessSampleAPI(IdExtractorCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	tykMiddleware := &TykMiddleware{spec, proxy}

	newExtractor(spec, tykMiddleware)

	var thisExtractor IdExtractor
	thisExtractor = tykMiddleware.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	thisSession := createBasicAuthSession()
	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	// req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedPass))

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(*spec)
	chain.ServeHTTP(recorder, req)

	var returnOverrides ReturnOverrides
	_, returnOverrides = thisExtractor.ExtractAndCheck(req)

	if returnOverrides.ResponseCode != 400 && returnOverrides.ResponseError != "Authorization field missing" {
		t.Fatal("ValueExtractor should return an error when the header is missing.")
	}
}

/* Regex Extractor tests, using "header" source */

func TestRegexExtractorHeaderSource(t *testing.T) {
	spec := MakeCoProcessSampleAPI(RegexExtractorDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	tykMiddleware := &TykMiddleware{spec, proxy}

	newExtractor(spec, tykMiddleware)

	var thisExtractor IdExtractor
	thisExtractor = tykMiddleware.Spec.CustomMiddleware.IdExtractor.Extractor.(IdExtractor)

	thisSession := createBasicAuthSession()

	// Basic auth sessions are stored as {org-id}{username}, so we need to append it here when we create the session.
	spec.SessionManager.UpdateSession("default4321", thisSession, 60)

	fullHeaderValue := "token-12345"
	matchedHeaderValue := []byte("12345")

	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("Authorization", fullHeaderValue)

	if err != nil {
		t.Fatal(err)
	}

	chain := getBasicAuthChain(*spec)
	chain.ServeHTTP(recorder, req)

	// var returnOverrides ReturnOverrides
	var SessionID string

	SessionID, _ = thisExtractor.ExtractAndCheck(req)
	expectedSessionID := computeSessionID(matchedHeaderValue, tykMiddleware)

	if SessionID != expectedSessionID {
		t.Fatal("Regex Extractor output doesn't match the computed session ID.")
	}

}

func computeSessionID(input []byte, tykMiddleware *TykMiddleware) (sessionID string) {
	tokenID := fmt.Sprintf("%x", md5.Sum(input))
	sessionID = tykMiddleware.Spec.OrgID + tokenID

	return sessionID
}

var IdExtractorCoProcessDef string = `

	{
		"name": "Tyk Test API",
		"api_id": "1",
		"org_id": "default",
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
				"v1": {
					"name": "v1",
					"expires": "2100-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"event_handlers": {
			"events": {
				"AuthFailure": [
								{
										"handler_name":"cp_dynamic_handler",
										"handler_meta": {
												"name": "my_handler"
										}
								}
						]
			}
		},
		"custom_middleware": {
      "pre": [
        {
          "name": "MyPreMiddleware",
          "require_session": false
        }
      ],
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
			"target_url": "http://httpbin.org",
			"strip_listen_path": false
		}
	}
`

var RegexExtractorDef string = `

	{
		"name": "Tyk Test API - ValueExtractor/XPath",
		"api_id": "1",
		"org_id": "default",
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
				"v1": {
					"name": "v1",
					"expires": "2100-01-02 15:04",
					"use_extended_paths": true,
					"paths": {
						"ignored": [],
						"white_list": [],
						"black_list": []
					}
				}
			}
		},
		"event_handlers": {
			"events": {
				"AuthFailure": [
								{
										"handler_name":"cp_dynamic_handler",
										"handler_meta": {
												"name": "my_handler"
										}
								}
						]
			}
		},
		"custom_middleware": {
			"id_extractor": {
        "extract_from": "header",
        "extract_with": "regex",
        "extractor_config": {
          "header_name": "Authorization",
          "regex_expression": "[^\\\\-]+"
        }
      },
      "driver": "grpc"
    },
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://httpbin.org",
			"strip_listen_path": false
		}
	}
`
