package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
)

var ipMiddlewareTestDefinitionEnabledFail = `

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
			"target_url": "http://example.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": true,
		"allowed_ips": ["12.12.12.12"]
	}
`

var ipMiddlewareTestDefinitionEnabledPass = `

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
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": true,
		"allowed_ips": ["127.0.0.1", "127.0.0.1/24"]
	}
`

var ipMiddlewareTestDefinitionDisabled = `

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
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		},
		"enable_ip_whitelisting": false,
		"allowed_ips": []
	}
`

var ipMiddlewareTestDefinitionMissing = `

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
		"proxy": {
			"listen_path": "/v1",
			"target_url": "http://example.com",
			"strip_listen_path": false
		}
	}
`

func makeIPSampleAPI(apiTestDef string) *APISpec {
	log.Debug("CREATING TEMPORARY API FOR IP WHITELIST")
	thisSpec := createDefinitionFromString(apiTestDef)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	thisSpec.Init(&redisStore, &redisStore, healthStore, orgStore)

	specs := &[]*APISpec{thisSpec}
	newMuxes := mux.NewRouter()
	loadAPIEndpoints(newMuxes)
	loadApps(specs, newMuxes)
	newHttpMuxer := http.NewServeMux()
	newHttpMuxer.Handle("/", newMuxes)

	http.DefaultServeMux = newHttpMuxer
	log.Debug("IP TEST Reload complete")

	return thisSpec
}

func TestIpMiddlewareIPFail(t *testing.T) {
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionEnabledFail)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234wer", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionEnabledPass)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("gfgg1234", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionMissing)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234rtyrty", thisSession, 60)
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
	spec := makeIPSampleAPI(ipMiddlewareTestDefinitionDisabled)
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("1234iuouio", thisSession, 60)
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
