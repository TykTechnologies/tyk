package main

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransformResponseWithURLRewrite(t *testing.T) {
	testTemplateBlob := base64.StdEncoding.EncodeToString([]byte(`{"http_method":"{{.Method}}"}`))

	testData := map[string]struct {
		apiSpec      string
		url          string
		expectedCode int
		expectedBody string
	}{
		"just_transform_response": {
			apiSpec: `
			{
				"api_id": "1",
				"auth": {"auth_header_name": "authorization"},
				"version_data": {
					"not_versioned": true,
					"versions": {
						"v1": {
							"name": "v1",
							"use_extended_paths": true,
							"extended_paths": {
								"transform_response": [
									{
										"path": "get",
										"method": "GET",
										"template_data": {
											"template_mode": "blob",
											"template_source": "` + testTemplateBlob + `"
										}
									}
								]
							}
						}
					}
				},
				"response_processors":[{"name": "response_body_transform"}],
				"proxy": {
					"listen_path": "/v1",
					"target_url": "` + testHttpAny + `"
				}
			}
			`,
			url:          "/v1/get",
			expectedCode: http.StatusOK,
			expectedBody: `{"http_method":"GET"}`,
		},
		"transform_path_equal_to_rewrite_to": {
			apiSpec: `
			{
				"api_id": "1",
				"auth": {"auth_header_name": "authorization"},
				"version_data": {
					"not_versioned": true,
					"versions": {
						"v1": {
							"name": "v1",
							"use_extended_paths": true,
							"extended_paths": {
								"url_rewrites": [
									{
									  "path": "abc",
									  "method": "GET",
									  "match_pattern": "abc",
									  "rewrite_to": "get"
									}
								],
								"transform_response": [
									{
										"path": "get",
										"method": "GET",
										"template_data": {
											"template_mode": "blob",
											"template_source": "` + testTemplateBlob + `"
										}
									}
								]
							}
						}
					}
				},
				"response_processors":[{"name": "response_body_transform"}],
				"proxy": {
					"listen_path": "/v1",
					"target_url": "` + testHttpAny + `"
				}
			}
			`,
			url:          "/v1/abc",
			expectedCode: http.StatusOK,
			expectedBody: `{"http_method":"GET"}`,
		},
		"transform_path_equal_to_rewrite_path": {
			apiSpec: `
			{
				"api_id": "1",
				"auth": {"auth_header_name": "authorization"},
				"version_data": {
					"not_versioned": true,
					"versions": {
						"v1": {
							"name": "v1",
							"use_extended_paths": true,
							"extended_paths": {
								"url_rewrites": [
									{
									  "path": "abc",
									  "method": "GET",
									  "match_pattern": "abc",
									  "rewrite_to": "get"
									}
								],
								"transform_response": [
									{
										"path": "abc",
										"method": "GET",
										"template_data": {
											"template_mode": "blob",
											"template_source": "` + testTemplateBlob + `"
										}
									}
								]
							}
						}
					}
				},
				"response_processors":[{"name": "response_body_transform"}],
				"proxy": {
					"listen_path": "/v1",
					"target_url": "` + testHttpAny + `"
				}
			}
			`,
			url:          "/v1/abc",
			expectedCode: http.StatusOK,
			expectedBody: `{"http_method":"GET"}`,
		},
	}

	for testName, test := range testData {
		spec := createSpecTest(t, test.apiSpec)
		session := createNonThrottledSession()
		spec.SessionManager.UpdateSession("1234wer", session, 60)

		recorder := httptest.NewRecorder()
		req := testReq(t, http.MethodGet, test.url, nil)
		req.Header.Set("authorization", "1234wer")
		req.RemoteAddr = "127.0.0.1:80"

		chain := getChain(spec)
		chain.ServeHTTP(recorder, req)

		if recorder.Code != 200 {
			t.Fatalf("[%s] Invalid response code %d, should be 200\n", testName, recorder.Code)
		}

		// check that body was transformed
		resp := recorder.Result()
		bodyData, _ := ioutil.ReadAll(resp.Body)
		body := string(bodyData)
		if body != test.expectedBody {
			t.Fatalf("[%s] Expected response body: '%s' Got response body: %s\n", testName, test.expectedBody, body)
		}
	}
}
