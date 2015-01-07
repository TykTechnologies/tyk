package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)

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
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
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
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
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
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
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
	healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
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
