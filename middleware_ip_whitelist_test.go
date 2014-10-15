package main

import (
	"net/http"
	"net/url"
	"testing"
	"net/http/httptest"
)

var ipMiddlewareTestDefinitionEnabledFail string = `

	{
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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": true,
		"allowed_ips": ["12.12.12.12"]
	}
`

var ipMiddlewareTestDefinitionEnabledPass string = `

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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": true,
		"allowed_ips": ["127.0.0.1"]
	}
`

var ipMiddlewareTestDefinitionDisabled string = `

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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": false,
		"allowed_ips": []
	}
`

var ipMiddlewareTestDefinitionMissing string = `

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
			"target_url": "http://lonelycode.com",
			"strip_listen_path": false
		}
	}
`

func MakeIPSampleAPI(apiTestDef string) *APISpec {
	log.Warning("CREATING TEMPORARY API FOR IP WHITELIST")
	thisSpec := createDefinitionFromString(apiTestDef)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	thisSpec.Init(&redisStore, &redisStore)

	specs := []APISpec{thisSpec}
	newMuxes := http.NewServeMux()
	loadAPIEndpoints(newMuxes)
	loadApps(specs, newMuxes)

	http.DefaultServeMux = newMuxes
	log.Warning("IP TEST Reload complete")

	return &thisSpec
}

func TestIpMiddlewareIPFail(t *testing.T) {
	spec := MakeIPSampleAPI(ipMiddlewareTestDefinitionEnabledFail)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createThrottledSession()
	spec.SessionManager.UpdateSession("1234", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.1"
	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(*spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Error("Invalid response code, should be 403:  \n", recorder.Code, recorder.Body)
	}
}

func TestIpMiddlewareIPPass(t *testing.T) {
	spec := MakeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createThrottledSession()
	spec.SessionManager.UpdateSession("1234", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.RemoteAddr = "127.0.0.1"
	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(*spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body, req.RemoteAddr)
	}
}

func TestIpMiddlewareIPMissing(t *testing.T) {
	spec := MakeIPSampleAPI(ipMiddlewareTestDefinitionMissing)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createThrottledSession()
	spec.SessionManager.UpdateSession("1234", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(*spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}


func TestIpMiddlewareIPDisabled(t *testing.T) {
	spec := MakeIPSampleAPI(ipMiddlewareTestDefinitionDisabled)
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}
	spec.Init(&redisStore, &redisStore)
	thisSession := createThrottledSession()
	spec.SessionManager.UpdateSession("1234", thisSession, 60)
	uri := "/about-lonelycoder/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(*spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Invalid response code, should be 200:  \n", recorder.Code, recorder.Body)
	}
}

//func TestIpMiddlewareConfigMissing(t *testing.T) {
//	uri := "/v1/bananaphone"
//	method := "GET"
//
//	param := make(url.Values)
//	req, err := http.NewRequest(method, uri+param.Encode(), nil)
//	req.Header.Add("version", "v1")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	thisSpec := MakeIPSampleAPI(ipMiddlewareTestDefinitionMissing)
//
//	ok, status := thisSpec.IsRequestValid(req)
//	if !ok {
//		t.Error("Request should pass as no IP whitelisting in place: ", status)
//	}
//}
//
//func TestIpMiddlewareConfigDisabled(t *testing.T) {
//	uri := "/v1/bananaphone"
//	method := "GET"
//
//	param := make(url.Values)
//	req, err := http.NewRequest(method, uri+param.Encode(), nil)
//	req.Header.Add("version", "v1")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	thisSpec := MakeIPSampleAPI(ipMiddlewareTestDefinitionDisabled)
//
//	ok, status := thisSpec.IsRequestValid(req)
//	if !ok {
//		t.Error("Request should pass as IP whitelisting disabled: ", status)
//	}
//}
//
//func TestIpMiddlewareIPPass(t *testing.T) {
//	uri := "/v1/bananaphone"
//	method := "GET"
//
//	param := make(url.Values)
//	req, err := http.NewRequest(method, uri+param.Encode(), nil)
//	req.Header.Add("version", "v1")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	thisSpec := MakeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
//
//	ok, status := thisSpec.IsRequestValid(req)
//	if !ok {
//		t.Error("Request should pass as IP is in whitelist: ", status)
//	}
//}
//
//func TestIpMiddlewareIPFail(t *testing.T) {
//	uri := "/v1/bananaphone"
//	method := "GET"
//
//	param := make(url.Values)
//	req, err := http.NewRequest(method, uri+param.Encode(), nil)
//	req.Header.Add("version", "v1")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	thisSpec := MakeIPSampleAPI(ipMiddlewareTestDefinitionEnabledFail)
//
//	ok, status := thisSpec.IsRequestValid(req)
//	if ok {
//		t.Error("Request should fail as IP is not in whitelist: ", status)
//	}
//}
