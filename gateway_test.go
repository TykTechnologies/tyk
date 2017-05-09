package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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

var (
	// to register to, but never used
	discardMuxer = mux.NewRouter()

	// to simulate time ticks for tests that do reloads
	reloadTick = make(chan time.Time)
)

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
	testHttpJWK  = testHttpAny + "/jwk.json"

	// 16501 port should not be bind to anything, and can be used for testing failures
	testHttpFailure     = "127.0.0.1:16501"
	testHttpFailureAny  = "http://" + testHttpFailure
	testHttpFailureGet  = testHttpFailureAny + "/get"
	testHttpFailurePost = testHttpFailureAny + "/post"
)

type testHttpResponse struct {
	Method  string
	Url     string
	Headers map[string]string
	Form    map[string]string
}

func testHttpHandler() http.Handler {
	httpError := func(w http.ResponseWriter, status int) {
		http.Error(w, http.StatusText(status), status)
	}
	writeDetails := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusInternalServerError)
			return
		}
		err := json.NewEncoder(w).Encode(testHttpResponse{
			Method:  r.Method,
			Url:     r.URL.String(),
			Headers: firstVals(r.Header),
			Form:    firstVals(r.Form),
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
	mux.HandleFunc("/jwk.json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, jwkTestJson)
	})
	return mux
}

const jwkTestJson = `{
	"keys": [{
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig",
		"x5c": ["Ci0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeXFaNHJ3S0Y4cUNFeFM3a3BZNGMKbkphLzM3Rk1rSk5rYWxaM091c2xMQjBvUkw4VDRjOTRrZEY0YWVOelNGa1NlMm45OUlCSTZTc2w3OXZiZk1aYgordDA2TDBROTRrKy9QMzd4NysvUkpaaWZmNHkxVkdqcm5ybk1JMml1OWw0aUJCUll6Tm1HNmVibHJvRU1NV2xnCms1dHlzSGd4QjU5Q1NOSWNEOWdxazFoeDRuL0ZnT212S3NmUWdXSE5sUFNEVFJjV0dXR2hCMi9YZ05WWUcycE8KbFF4QVBxTGhCSGVxR1RYQmJQZkdGOWNIeml4cHNQcjZHdGJ6UHdoc1EvOGJQeG9KN2hkZm4rcnp6dGtzM2Q2KwpIV1VSY3lOVExSZTBtalhqamVlOVo2K2daK0grZlM0cG5QOXRxVDdJZ1U2ZVBVV1Rwam9pUHRMZXhnc0FhL2N0CmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="],
		"n": "xofiG8gsnv9-I_g-5OWTLhaZtgAGq1QEsBCPK9lmLqhuonHe8lT-nK1DM49f6J9QgaOjZ3DB50QkhBysnIFNcXFyzaYIPMoccvuHLPgdBawX4WYKm5gficD0WB0XnTt4sqTI5usFpuop9vvW44BwVGhRqMT7c11gA8TSWMBxDI4A5ARc4MuQtfm64oN-JQodSztArwb9wcmH8WrBvSUkR4pyi9MT8W27gqJ2e2Xn8jgGnswNQWOyCTN84PawOYaN-2ORHeIea1g-URln1bofcHN73vZCIrVbE6iA2D7Ybh22AVrCfunekEDEe2GZfLZLejiZiBWG7enJhcrQIzAQGw",
		"e": "AQAB",
		"kid": "12345",
		"x5t": "12345"
	}]
}`

func firstVals(vals map[string][]string) map[string]string {
	m := make(map[string]string, len(vals))
	for k, vs := range vals {
		m[k] = vs[0]
	}
	return m
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
	writeDefaultConf(&config)
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

	go reloadLoop(reloadTick)

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
func ProxyHandler(p *ReverseProxy, apiSpec *APISpec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tm := TykMiddleware{apiSpec, p}
		handler := SuccessHandler{&tm}
		// Skip all other execution
		handler.ServeHTTP(w, r)
	})
}

func getChain(spec *APISpec) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
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
						"target_path": "` + testHttpPost + `",
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
						"target_path": "` + testHttpPost + `",
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
		"target_url": "` + testHttpGet + `",
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

	form := url.Values{}
	form.Add("foo", "swiggetty")
	form.Add("bar", "swoggetty")
	form.Add("baz", "swoogetty")

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: ", recorder.Code)
		t.Error(recorder.Body)
	}

	var resp testHttpResponse
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatal("JSON decoding failed:", err)
	}

	if resp.Form["authorization"] != "54321" {
		t.Error("Request params did not arrive")
	}
	if resp.Form["foo"] != "swiggetty" {
		t.Error("Form param 1 did not arrive")
	}
	if resp.Form["bar"] != "swoggetty" {
		t.Error("Form param 2 did not arrive")
	}
	if resp.Form["baz"] != "swoogetty" {
		t.Error("Form param 3 did not arrive")
	}
}

func TestVersioningRequestOK(t *testing.T) {
	spec := createSpecTest(t, versionedDefinition)
	session := createVersionedSession()
	spec.SessionManager.UpdateSession("96869686969", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", "96869686969")
	req.Header.Add("version", "v1")

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

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", "zz1234")
	req.Header.Add("version", "v1")

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

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", uri, nil)

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
	uri := "/v1/allowed/whitelist/reply/"

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", keyId)

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
	defer spec.SessionManager.ResetQuota(keyId, session)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", keyId)

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code, " Header:", recorder.HeaderMap)
	}

	secondRecorder := httptest.NewRecorder()
	chain.ServeHTTP(secondRecorder, req)
	thirdRecorder := httptest.NewRecorder()
	chain.ServeHTTP(thirdRecorder, req)

	if thirdRecorder.Code != 403 {
		t.Error("Third request returned invalid code, should 403, got: \n", thirdRecorder.Code)
	}

	newAPIError := tykErrorResponse{}
	json.Unmarshal(thirdRecorder.Body.Bytes(), &newAPIError)

	if newAPIError.Error != "Quota exceeded" {
		t.Error("Third request returned invalid message, got: \n", newAPIError.Error)
	}
}

func TestWithAnalytics(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDefNoWhiteList)
	session := createNonThrottledSession()
	spec.SessionManager.UpdateSession("ert1234ert", session, 60)

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", "ert1234ert")

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

	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("authorization", "dfgjg345316ertdg")

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

type tykHttpTest struct {
	method, path string
	code         int
	data         string

	afterFn        func()
	adminAuth      bool
	controlRequest bool
}

func testHttp(t *testing.T, tests []tykHttpTest, separateControlPort bool) {
	var testMatrix = []struct {
		goagain          bool
		overrideDefaults bool
	}{
		{false, false},
		{false, true},
		{true, true},
		{true, false},
	}

	for _, m := range testMatrix {
		var ln, cln net.Listener

		ln, _ = net.Listen("tcp", ":0")

		if separateControlPort {
			cln, _ = net.Listen("tcp", ":0")

			_, port, _ := net.SplitHostPort(cln.Addr().String())
			config.ControlAPIPort, _ = strconv.Atoi(port)
		}

		if m.overrideDefaults {
			config.HttpServerOptions.OverrideDefaults = true
		} else {
			config.HttpServerOptions.OverrideDefaults = false
		}

		// Ensure that no local API's installed
		os.RemoveAll(config.AppPath)

		var err error
		config.AppPath, err = ioutil.TempDir("", "tyk-test-")
		if err != nil {
			panic(err)
		}

		initialiseSystem(nil)
		// This is emulate calling start()
		// But this lines is the only thing needed for this tests
		if config.ControlAPIPort == 0 {
			loadAPIEndpoints(defaultRouter)
		}

		if m.goagain {
			listen(ln, cln, nil)
		} else {
			listen(ln, cln, fmt.Errorf("Without goagain"))
		}

		client := &http.Client{}

		for ti, tc := range tests {
			tPrefix := ""
			if m.goagain {
				tPrefix += "[Goagain]"
			}
			if m.overrideDefaults {
				tPrefix += "[OverrideDefaults]"
			}
			if tc.adminAuth {
				tPrefix += "[Auth]"
			}
			if tc.controlRequest {
				tPrefix += "[Control]"
			}

			baseUrl := "http://" + ln.Addr().String()

			if tc.controlRequest {
				baseUrl = "http://" + cln.Addr().String()
			}

			var bodyReader io.Reader

			if tc.data != "" {
				bodyReader = strings.NewReader(tc.data)
			}

			req, _ := http.NewRequest(tc.method, baseUrl+tc.path, bodyReader)

			if tc.adminAuth {
				req.Header.Add("X-Tyk-Authorization", config.Secret)
			}

			resp, _ := client.Do(req)

			if resp.StatusCode != tc.code {
				t.Errorf("[%d]%s%s %s Status %d, want %d", ti, tPrefix, tc.method, tc.path, resp.StatusCode, tc.code)
			}

			if tc.afterFn != nil {
				tc.afterFn()
			}
		}

		ln.Close()

		if cln != nil {
			cln.Close()
		}
	}
}

const sampleAPI = `{
	"name": "API",
	"slug": "api",
	"api_id": "test",
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"Default": {
				"name": "Default",
				"expires": "3000-01-02 15:04"
			}
		}
	},
	"proxy": {
		"listen_path": "/",
		"target_url": "http://127.0.0.1:16500",
		"strip_listen_path": true
	},
	"active": true
}`

func TestListener(t *testing.T) {
	tests := []tykHttpTest{
		{method: "GET", path: "/", code: 404},
		{method: "GET", path: "/tyk/apis/", code: 403},
		{method: "GET", path: "/tyk/apis/", adminAuth: true, code: 200},
		{method: "GET", path: "/tyk/apis", code: 403},
		{method: "GET", path: "/tyk/apis", adminAuth: true, code: 200},
		{method: "POST", path: "/tyk/apis", data: sampleAPI, adminAuth: true, code: 200},
		// API definitions not reloaded yet
		{method: "GET", path: "/", code: 404},
		{method: "GET", path: "/tyk/reload/", adminAuth: true, code: 200, afterFn: func() { doReload() }},
		{method: "GET", path: "/", code: 200},
	}

	testHttp(t, tests, false)
	doReload()
	testHttp(t, tests, false)
}

// Admin api located on separate port
func TestControlListener(t *testing.T) {
	tests := []tykHttpTest{
		{method: "GET", path: "/", code: 404},
		{method: "GET", path: "/tyk/apis", code: 404},

		// Querying control API
		{method: "GET", path: "/", code: 404, controlRequest: true},
		{method: "GET", path: "/tyk/apis", code: 403, controlRequest: true},
		{method: "GET", path: "/tyk/apis/", code: 200, adminAuth: true, controlRequest: true},
	}

	testHttp(t, tests, true)
	doReload()
	testHttp(t, tests, true)
}

func TestManagementNodeRedisEvents(t *testing.T) {
	defer func() {
		config.ManagementNode = false
	}()
	config.ManagementNode = false
	msg := redis.Message{
		Data: []byte(`{"Command": "NoticeGatewayDRLNotification"}`),
	}
	shouldHandle := func(got NotificationCommand) {
		if want := NoticeGatewayDRLNotification; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, shouldHandle, nil)
	config.ManagementNode = true
	notHandle := func(got NotificationCommand) {
		t.Fatalf("should have not handled redis event")
	}
	handleRedisEvent(msg, notHandle, nil)
}
