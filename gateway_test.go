package main

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis"
	"github.com/justinas/alice"
)

func init() {
	runningTests = true
}

func TestMain(m *testing.M) {
	s, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer s.Close()
	config.Storage.Port, _ = strconv.Atoi(s.Port())
	initialiseSystem(map[string]interface{}{})
	os.Exit(m.Run())
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func createNonThrottledSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 100.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = 10
	thisSession.Alias = "TEST-ALIAS"

	return thisSession
}

func createQuotaSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 8.0
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 1.0
	thisSession.Expires = 0
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix() + 20
	thisSession.QuotaRemaining = 2
	thisSession.QuotaMax = 2

	return thisSession
}

func createVersionedSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 10000
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 60
	thisSession.Expires = -1
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = -1
	thisSession.AccessRights = map[string]AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v1"}}}

	return thisSession
}

func createParamAuthSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 10000
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 60
	thisSession.Expires = -1
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = -1
	thisSession.AccessRights = map[string]AccessDefinition{"9992": {APIName: "Tyk Test API", APIID: "9992", Versions: []string{"default"}}}

	return thisSession
}

func createStandardSession() SessionState {
	var thisSession SessionState
	thisSession.Rate = 10000
	thisSession.Allowance = thisSession.Rate
	thisSession.LastCheck = time.Now().Unix()
	thisSession.Per = 60
	thisSession.Expires = -1
	thisSession.QuotaRenewalRate = 300 // 5 minutes
	thisSession.QuotaRenews = time.Now().Unix()
	thisSession.QuotaRemaining = 10
	thisSession.QuotaMax = -1

	return thisSession
}

type TykErrorResponse struct {
	Error string
}

func getChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	//remote, _ := url.Parse("http://example.com/")
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

var nonExpiringDefNoWhiteList = `

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
			"target_url": "http://example.com/",
			"strip_listen_path": false
		}
	}

`

var VersionedDefinition = `

	{
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
			"target_url": "http://example.com/",
			"strip_listen_path": false
		}
	}

`

var PathBasedDefinition = `

	{
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
	}

`

var ExtendedPathGatewaySetup = `

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
			"target_url": "http://example.com/",
			"strip_listen_path": false
		}
	}
`

func createExtendedDefinitionWithPaths() *APISpec {
	return createDefinitionFromString(ExtendedPathGatewaySetup)
}

func createNonVersionedDefinition() *APISpec {
	return createDefinitionFromString(nonExpiringDefNoWhiteList)
}

func createVersionedDefinition() *APISpec {
	return createDefinitionFromString(VersionedDefinition)
}

func createPathBasedDefinition() *APISpec {
	return createDefinitionFromString(PathBasedDefinition)
}

func TestParambasedAuth(t *testing.T) {
	spec := createPathBasedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createParamAuthSession()
	spec.SessionManager.UpdateSession("54321", thisSession, 60)
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

// func TestThrottling(t *testing.T) {
// 	spec := createNonVersionedDefinition()
// 	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
// 	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
// 	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
// 	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
// 	thisSession := createThrottledSession()
// 	keyId := randSeq(10)
// 	spec.SessionManager.UpdateSession(keyId, thisSession, 60)
// 	uri := "/"
// 	method := "GET"

// 	recorder := httptest.NewRecorder()
// 	param := make(url.Values)
// 	req, err := http.NewRequest(method, uri+param.Encode(), nil)
// 	req.Header.Add("authorization", keyId)

// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	chain := getChain(spec)
// 	chain.ServeHTTP(recorder, req)

// 	if recorder.Code != 200 {
// 		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
// 	}

// 	secondRecorder := httptest.NewRecorder()
// 	chain.ServeHTTP(secondRecorder, req)

// 	if secondRecorder.Code != 200 {
// 		t.Error("Second request failed with non-200 code: \n", secondRecorder.Code)
// 	}

// 	thirdRecorder := httptest.NewRecorder()
// 	chain.ServeHTTP(thirdRecorder, req)

// 	if thirdRecorder.Code != 200 {
// 		t.Error("Third request failed, should be 200!: \n", thirdRecorder.Code)
// 	}

// 	fourthRecorder := httptest.NewRecorder()
// 	chain.ServeHTTP(fourthRecorder, req)

// 	if fourthRecorder.Code == 200 {
// 		t.Error("Fourth request passed, should not be 200!: \n", fourthRecorder.Code)
// 	}
// 	if fourthRecorder.Code != 429 {
// 		t.Error("Fourth request returned invalid code, should 403, got: \n", fourthRecorder.Code)
// 	}

// 	fifthRecorder := httptest.NewRecorder()
// 	chain.ServeHTTP(fifthRecorder, req)

// 	if fifthRecorder.Code == 200 {
// 		t.Error("5th request passed, should not be 200!: \n", fifthRecorder.Code)
// 	}
// 	if fifthRecorder.Code != 429 {
// 		t.Error("5th request returned invalid code, should 403, got: \n", fifthRecorder.Code)
// 	}

// 	newAPIError := TykErrorResponse{}
// 	json.Unmarshal([]byte(fifthRecorder.Body.String()), &newAPIError)

// 	if newAPIError.Error != "Rate limit exceeded" {
// 		t.Error("Last request returned invalid message, got: \n", fifthRecorder.Body.String())
// 	}
// }

func TestVersioningRequestOK(t *testing.T) {
	spec := createVersionedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createVersionedSession()
	spec.SessionManager.UpdateSession("96869686969", thisSession, 60)
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
	spec := createVersionedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createVersionedSession()
	thisSession.AccessRights = map[string]AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v2"}}}

	// no version allowed
	spec.SessionManager.UpdateSession("zz1234", thisSession, 60)
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
	spec := createExtendedDefinitionWithPaths()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createStandardSession()

	spec.SessionManager.UpdateSession("tyutyu345345dgh", thisSession, 60)
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
	spec := createExtendedDefinitionWithPaths()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createStandardSession()

	keyId := randSeq(10)

	spec.SessionManager.UpdateSession(keyId, thisSession, 60)
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
	spec := createNonVersionedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createQuotaSession()
	keyId := randSeq(10)
	spec.SessionManager.UpdateSession(keyId, thisSession, 60)
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

	newAPIError := TykErrorResponse{}
	json.Unmarshal([]byte(thirdRecorder.Body.String()), &newAPIError)

	if newAPIError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newAPIError.Error)
	}
}

func TestWithAnalyticsTestWithAnalytics(t *testing.T) {
	config.EnableAnalytics = true

	AnalyticsStore := RedisClusterStorageManager{KeyPrefix: "analytics-"}
	log.Info("Setting up analytics DB connection")

	analytics = RedisAnalyticsHandler{
		Store: &AnalyticsStore,
	}
	analytics.Store.Connect()
	analytics.Init()

	spec := createNonVersionedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("ert1234ert", thisSession, 60)
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
	config.EnableAnalytics = true

	AnalyticsStore := RedisClusterStorageManager{KeyPrefix: "analytics-"}
	log.Info("Setting up analytics DB connection")

	analytics = RedisAnalyticsHandler{
		Store: &AnalyticsStore,
	}
	analytics.Store.Connect()
	analytics.Init()

	spec := createNonVersionedDefinition()
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-"}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	orgStore := &RedisClusterStorageManager{KeyPrefix: "orgKey."}
	spec.Init(&redisStore, &redisStore, healthStore, orgStore)
	thisSession := createNonThrottledSession()
	spec.SessionManager.UpdateSession("fgh561234", thisSession, 60)
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
