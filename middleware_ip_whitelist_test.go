package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const ipMiddlewareTestDefinitionEnabledFail = `{
	"name": "Tyk Test API - IPCONF Fail",
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
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	},
	"enable_ip_whitelisting": true,
	"allowed_ips": ["12.12.12.12"]
}`

const ipMiddlewareTestDefinitionEnabledPass = `{
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
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	},
	"enable_ip_whitelisting": true,
	"allowed_ips": ["127.0.0.1", "127.0.0.1/24"]
}`

const ipMiddlewareTestDefinitionDisabled = `{
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
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	},
	"enable_ip_whitelisting": false,
	"allowed_ips": []
}`

const ipMiddlewareTestDefinitionMissing = `{
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
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	}
}`

func createIPSampleAPI(t *testing.T, apiTestDef string) *APISpec {
	spec := createSpecTest(t, apiTestDef)
	loadApps([]*APISpec{spec}, discardMuxer)
	return spec
}

func TestIpMiddlewareIPFail(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionEnabledFail)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234wer", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.1"
	req.Header.Add("authorization", "1234wer")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Invalid response code, should be 403:  \n", recorder.Code, recorder.Body)
	}
}

func TestIpMiddlewareIPPass(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionEnabledPass)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.1"
	req.Header.Add("authorization", "gfgg1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
	}
}

func TestIpMiddlewareIPPassCIDR(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionEnabledPass)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.2"
	req.Header.Add("authorization", "gfgg1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
	}
}

func TestIPMiddlewareIPFailXForwardedFor(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionEnabledPass)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "10.0.0.1"
	req.Header.Add("authorization", "gfgg1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Invalid response code, should be 403:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
	}
}

func TestIPMiddlewareIPPassXForwardedFor(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionEnabledPass)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "10.0.0.1"
	req.Header.Add("X-Forwarded-For", "127.0.0.1")
	req.Header.Add("authorization", "gfgg1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
	}
}

func TestIpMiddlewareIPMissing(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionMissing)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234rtyrty", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "1234rtyrty")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}

func TestIpMiddlewareIPDisabled(t *testing.T) {
	spec := createIPSampleAPI(t, ipMiddlewareTestDefinitionDisabled)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234iuouio", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "1234iuouio")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}
