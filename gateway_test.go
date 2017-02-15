package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
)

func init() {
	runningTests = true
}

// to register to, but never used
var discardMuxer = mux.NewRouter()

const (
	// we need a static port so that the urls can be used in static
	// test data and the requests aren't randomized for checksums
	// port 16500 should be obscure and unused
	testHttpListen = "127.0.0.1:16500"
	// accepts any http requests on /, only allows GET on /get, etc
	// all return a JSON with request info
	testHttpAny  = "http://" + testHttpListen
	testHttpGet  = testHttpAny + "/get"
	testHttpPost = testHttpAny + "/post"
	testHttpPut  = testHttpAny + "/put"
)

func testHttpHandler() http.Handler {
	httpError := func(w http.ResponseWriter, status int) {
		http.Error(w, http.StatusText(status), status)
	}
	writeDetails := func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"method":  r.Method,
			"url":     r.URL.String(),
			"headers": r.Header,
			"body":    string(body),
		})
		if err != nil {
			httpError(w, http.StatusInternalServerError)
		}
	}
	handleMethod := func(method string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if method != "" && r.Method != method {
				httpError(w, http.StatusMethodNotAllowed)
			} else {
				writeDetails(w, r)
			}
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleMethod(""))
	mux.HandleFunc("/get", handleMethod("GET"))
	mux.HandleFunc("/post", handleMethod("POST"))
	mux.HandleFunc("/put", handleMethod("PUT"))
	return mux
}

func TestMain(m *testing.M) {
	testServer := &http.Server{
		Addr:           testHttpListen,
		Handler:        testHttpHandler(),
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		panic(testServer.ListenAndServe())
	}()
	WriteDefaultConf(&config)
	config.Storage.Database = 1
	if err := emptyRedis(); err != nil {
		panic(err)
	}
	var err error
	config.AppPath, err = ioutil.TempDir("", "tyk-test-")
	if err != nil {
		panic(err)
	}
	config.EnableAnalytics = true
	config.AnalyticsConfig.EnableGeoIP = true
	config.AnalyticsConfig.GeoIPDBLocation = filepath.Join("testdata", "MaxMind-DB-test-ipv4-24.mmdb")
	config.EnableJSVM = true
	config.Monitor.EnableTriggerMonitors = true
	config.AnalyticsConfig.NormaliseUrls.Enabled = true
	initialiseSystem(nil)
	if analytics.GeoIPDB == nil {
		panic("GeoIPDB was not initialized")
	}
	exitCode := m.Run()

	os.RemoveAll(config.AppPath)
	os.Exit(exitCode)
}

func emptyRedis() error {
	addr := ":" + strconv.Itoa(config.Storage.Port)
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("could not connect to redis: %v", err)
	}
	defer c.Close()
	dbName := strconv.Itoa(config.Storage.Database)
	if _, err := c.Do("SELECT", dbName); err != nil {
		return err
	}
	_, err = c.Do("FLUSHDB")
	return err
}

func createNonThrottledSession() (session SessionState) {
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.Expires = 0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10
	session.Alias = "TEST-ALIAS"
	return
}

func createQuotaSession() (session SessionState) {
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.Expires = 0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 2
	session.QuotaMax = 2
	return
}

func createVersionedSession() (session SessionState) {
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.AccessRights = map[string]AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v1"}}}
	return
}

func createParamAuthSession() (session SessionState) {
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.AccessRights = map[string]AccessDefinition{"9992": {APIName: "Tyk Test API", APIID: "9992", Versions: []string{"default"}}}
	return
}

func createStandardSession() (session SessionState) {
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	return
}

type tykErrorResponse struct {
	Error string
}

// ProxyHandler Proxies requests through to their final destination, if they make it through the middleware chain.
func ProxyHandler(p *ReverseProxy, apiSpec *APISpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tm := TykMiddleware{apiSpec, p}
		handler := SuccessHandler{&tm}
		// Skip all other execution
		handler.ServeHTTP(w, r)
		return
	}
}

func getChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
	tykMiddleware := &TykMiddleware{spec, proxy}
	chain := alice.New(
		CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
		CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
		CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

	return chain
}

const nonExpiringDefNoWhiteList = `{
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
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": [],
					"black_list": [],
					"white_list": []
				}
			}
		}
	},
	"event_handlers": {
		"events": {
			"QuotaExceeded": [
				{
					"handler_name":"eh_log_handler",
					"handler_meta": {
						"prefix": "LOG-HANDLER-PREFIX"
					}
				},
				{
					"handler_name":"eh_web_hook_handler",
					"handler_meta": {
						"method": "POST",
						"target_path": "http://posttestserver.com/post.php?dir=tyk-event-test",
						"template_path": "templates/default_webhook.json",
						"header_map": {"X-Tyk-Test-Header": "Tyk v1.BANANA"},
						"event_timeout": 10
					}
				}
			]
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	}
}`

const versionedDefinition = `{
	"name": "Tyk Test API",
	"api_id": "9991",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": false,
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04",
				"use_extended_paths": true,
				"paths": {
					"ignored": [],
					"black_list": [],
					"white_list": []
				}
			}
		}
	},
	"event_handlers": {
		"events": {
			"QuotaExceeded": [
				{
					"handler_name":"eh_log_handler",
					"handler_meta": {
						"prefix": "LOG-HANDLER-PREFIX"
					}
				},
				{
					"handler_name":"eh_web_hook_handler",
					"handler_meta": {
						"method": "POST",
						"target_path": "http://posttestserver.com/post.php?dir=tyk-event-test",
						"template_path": "templates/default_webhook.json",
						"header_map": {"X-Tyk-Test-Header": "Tyk v1.BANANA"},
						"event_timeout": 10
					}
				}
			]
		}
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + testHttpAny + `",
		"strip_listen_path": false
	}
}`

const pathBasedDefinition = `{
	"name": "Tyk Test API",
	"api_id": "9992",
	"org_id": "default",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {
		"use_param": true,
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"default": {
				"name": "default",
				"expires": "3000-01-02 15:04",
				"use_extended_paths": true,
				"paths": {
					"ignored": [],
					"black_list": [],
					"white_list": []
				}
			}
		}
	},
	"event_handlers": {},
	"proxy": {
		"listen_path": "/pathBased/",
		"target_url": "http://httpbin.org/",
		"strip_listen_path": true
	}
}`

const extendedPathGatewaySetup = `{
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
			"Default": {
				"name": "Default",
				"expires": "3000-01-02 15:04",
				"paths": {
					"ignored": [],
					"white_list": [],
					"black_list": []
				},
				"use_extended_paths": true,
				"extended_paths": {
					"ignored": [
						{
							"path": "/v1/ignored/noregex",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "/v1/ignored/with_id/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					],
					"white_list": [
						{
							"path": "v1/allowed/whitelist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/allowed/whitelist/reply/{id}",
							"method_actions": {
								"GET": {
									"action": "reply",
									"code": 200,
									"data": "flump",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/allowed/whitelist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					],
					"black_list": [
						{
							"path": "v1/disallowed/blacklist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "v1/disallowed/blacklist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"data": "",
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						}
					]
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

func testName(t *testing.T) string {
	// TODO(mvdan): replace with t.Name() once 1.9 is out and we
	// drop support for 1.7.x (approx July 2017)
	v := reflect.Indirect(reflect.ValueOf(t))
	return v.FieldByName("name").String()
}

func createSpecTest(t *testing.T, def string) *APISpec {
	spec := createDefinitionFromString(def)
	tname := testName(t)
	redisStore := &RedisClusterStorageManager{KeyPrefix: tname + "-apikey."}
	healthStore := &RedisClusterStorageManager{KeyPrefix: tname + "-apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: tname + "-orgKey."}
	spec.Init(redisStore, redisStore, healthStore, orgStore)
	return spec
}

func testKey(t *testing.T, name string) string {
	return fmt.Sprintf("%s-%s", testName(t), name)
}

func TestParambasedAuth(t *testing.T) {
	spec := createSpecTest(t, pathBasedDefinition)
	session := createParamAuthSession()
	spec.SessionManager.UpdateSession("54321", session, 60)
	uri := "/pathBased/post?authorization=54321"
	method := "POST"

	form := url.Values{}
	form.Add("foo", "swiggetty")
	form.Add("bar", "swoggetty")
	form.Add("baz", "swoogetty")

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: ", recorder.Code)
		log.Error("URI: ", uri)
		log.Error("Proxy To:", spec.Proxy.TargetURL)
		t.Error(recorder.Body)
	}

	// Ensure the post data is still sent
	contents, _ := ioutil.ReadAll(recorder.Body)
	dat := make(map[string]interface{})

	if err := json.Unmarshal(contents, &dat); err != nil {
		t.Fatal("JSON decoding failed:", err)
	}

	args, ok := dat["args"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid response")
	}
	if args["authorization"].(string) != "54321" {
		t.Error("Request params did not arrive")
	}
	fmap, ok := dat["form"].(map[string]interface{})
	if !ok {
		t.Fatal("Invalid response")
	}
	if fmap["foo"].(string) != "swiggetty" {
		t.Error("Form param 1 did not arrive")
	}
	if fmap["bar"].(string) != "swoggetty" {
		t.Error("Form param 2 did not arrive")
	}
	if fmap["baz"].(string) != "swoogetty" {
		t.Error("Form param 3 did not arrive")
	}

}

func TestVersioningRequestOK(t *testing.T) {
	spec := createSpecTest(t, versionedDefinition)
	session := createVersionedSession()
	spec.SessionManager.UpdateSession("96869686969", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "96869686969")
	req.Header.Add("version", "v1")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}
}

func TestVersioningRequestFail(t *testing.T) {
	spec := createSpecTest(t, versionedDefinition)
	session := createVersionedSession()
	session.AccessRights = map[string]AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v2"}}}

	// no version allowed
	spec.SessionManager.UpdateSession("zz1234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "zz1234")
	req.Header.Add("version", "v1")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed as version not defined for user: \n", recorder.Code)
	}
}

func TestIgnoredPathRequestOK(t *testing.T) {
	spec := createSpecTest(t, extendedPathGatewaySetup)
	session := createStandardSession()

	spec.SessionManager.UpdateSession("tyutyu345345dgh", session, 60)
	uri := "/v1/ignored/noregex"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	// No auth information, it's an ignored path!
	//	req.Header.Add("authorization", "1234")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request should have failed as version not defined for user: \n", recorder.Code)
	}
}

func TestWhitelistRequestReply(t *testing.T) {
	spec := createSpecTest(t, extendedPathGatewaySetup)
	session := createStandardSession()

	keyId := testKey(t, "key")

	spec.SessionManager.UpdateSession(keyId, session, 60)
	uri := "v1/allowed/whitelist/reply/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)

	req.Header.Add("authorization", keyId)

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	contents, _ := ioutil.ReadAll(recorder.Body)

	if string(contents) != "flump" {
		t.Error("Request body is incorrect! Is: ", string(contents))
	}
}

func TestQuota(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDefNoWhiteList)
	session := createQuotaSession()
	keyId := testKey(t, "key")
	spec.SessionManager.UpdateSession(keyId, session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", keyId)

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code, " Header:", recorder.HeaderMap)

	}

	secondRecorder := httptest.NewRecorder()
	chain.ServeHTTP(secondRecorder, req)
	thirdRecorder := httptest.NewRecorder()
	chain.ServeHTTP(thirdRecorder, req)

	if thirdRecorder.Code == 200 {
		t.Error("Third request failed, should not be 200!: \n", thirdRecorder.Code)
	}
	if thirdRecorder.Code != 403 {
		t.Error("Third request returned invalid code, should 403, got: \n", thirdRecorder.Code)
	}

	newAPIError := tykErrorResponse{}
	json.Unmarshal([]byte(thirdRecorder.Body.String()), &newAPIError)

	if newAPIError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newAPIError.Error)
	}
}

func TestWithAnalytics(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDefNoWhiteList)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("ert1234ert", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "ert1234ert")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}

	results := analytics.Store.GetKeysAndValues()

	if len(results) < 1 {
		t.Error("Not enough results! Should be 1, is: ", len(results))
	}

}

func TestWithAnalyticsErrorResponse(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDefNoWhiteList)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("fgh561234", session, 60)
	uri := "/"
	method := "GET"

	recorder := httptest.NewRecorder()
	param := make(url.Values)
	req, err := http.NewRequest(method, uri+param.Encode(), nil)
	req.Header.Add("authorization", "dfgjg345316ertdg")

	if err != nil {
		t.Fatal(err)
	}

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)
	chain.ServeHTTP(recorder, req)

	if recorder.Code == 200 {
		t.Error("Request failed with 200 code: \n", recorder.Code)
	}

	results := analytics.Store.GetKeysAndValues()
	if len(results) < 1 {
		t.Error("Not enough results! Should be 1, is: ", len(results))
	}

}
