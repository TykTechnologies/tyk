package main

import (
	"bytes"
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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
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
	// We need a static port so that the urls can be used in static
	// test data, and to prevent the requests from being randomized
	// for checksums. Port 16500 should be obscure and unused.
	testHttpListen = "127.0.0.1:16500"
	// Accepts any http requests on /, only allows GET on /get, etc.
	// All return a JSON with request info.
	testHttpAny  = "http://" + testHttpListen
	testHttpGet  = testHttpAny + "/get"
	testHttpPost = testHttpAny + "/post"
	testHttpJWK  = testHttpAny + "/jwk.json"

	// Nothing should be listening on port 16501 - useful for
	// testing TCP and HTTP failures.
	testHttpFailure    = "127.0.0.1:16501"
	testHttpFailureAny = "http://" + testHttpFailure
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
	if err := config.WriteDefault("", &config.Global); err != nil {
		panic(err)
	}
	config.Global.Storage.Database = 1
	if err := emptyRedis(); err != nil {
		panic(err)
	}
	var err error
	config.Global.AppPath, err = ioutil.TempDir("", "tyk-test-")
	if err != nil {
		panic(err)
	}
	config.Global.EnableAnalytics = true
	config.Global.AnalyticsConfig.EnableGeoIP = true
	config.Global.AnalyticsConfig.GeoIPDBLocation = filepath.Join("testdata", "MaxMind-DB-test-ipv4-24.mmdb")
	config.Global.EnableJSVM = true
	config.Global.Monitor.EnableTriggerMonitors = true
	config.Global.AnalyticsConfig.NormaliseUrls.Enabled = true
	afterConfSetup(&config.Global)
	initialiseSystem()
	// Small part of start()
	loadAPIEndpoints(mainRouter)
	if analytics.GeoIPDB == nil {
		panic("GeoIPDB was not initialized")
	}

	go reloadLoop(reloadTick)
	go reloadQueueLoop()

	go func() {
		// simulate reloads in the background, i.e. writes to
		// global variables that should not be accessed in a
		// racy way like the policies and api specs maps.
		for {
			policiesMu.Lock()
			policiesByID["_"] = user.Policy{}
			delete(policiesByID, "_")
			policiesMu.Unlock()
			apisMu.Lock()
			apisByID["_"] = nil
			delete(apisByID, "_")
			apisMu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	exitCode := m.Run()

	os.RemoveAll(config.Global.AppPath)
	os.Exit(exitCode)
}

func emptyRedis() error {
	addr := config.Global.Storage.Host + ":" + strconv.Itoa(config.Global.Storage.Port)
	c, err := redis.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("could not connect to redis: %v", err)
	}
	defer c.Close()
	dbName := strconv.Itoa(config.Global.Storage.Database)
	if _, err := c.Do("SELECT", dbName); err != nil {
		return err
	}
	_, err = c.Do("FLUSHDB")
	return err
}

func createNonThrottledSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 100.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = 10
	session.Alias = "TEST-ALIAS"
	return session
}

func createQuotaSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 8.0
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 1.0
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
	session.QuotaRemaining = 2
	session.QuotaMax = 2
	return session
}

func createVersionedSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.AccessRights = map[string]user.AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v1"}}}
	return session
}

func createParamAuthSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	session.AccessRights = map[string]user.AccessDefinition{"9992": {APIName: "Tyk Test API", APIID: "9992", Versions: []string{"default"}}}
	return session
}

func createStandardSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix()
	session.QuotaRemaining = 10
	session.QuotaMax = -1
	return session
}

type tykErrorResponse struct {
	Error string
}

// ProxyHandler Proxies requests through to their final destination, if they make it through the middleware chain.
func ProxyHandler(p *ReverseProxy, apiSpec *APISpec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseMid := BaseMiddleware{apiSpec, p}
		handler := SuccessHandler{baseMid}
		// Skip all other execution
		handler.ServeHTTP(w, r)
	})
}

func getChain(spec *APISpec) http.Handler {
	remote, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		panic(err)
	}
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	chain := alice.New(mwList(
		&IPWhiteListMiddleware{baseMid},
		&MiddlewareContextVars{BaseMiddleware: baseMid},
		&AuthKey{baseMid},
		&VersionCheck{BaseMiddleware: baseMid},
		&KeyExpired{baseMid},
		&AccessRightsCheck{baseMid},
		&RateLimitAndQuotaCheck{baseMid},
		&TransformHeaders{baseMid},
	)...).Then(proxyHandler)
	return chain
}

const nonExpiringDefNoWhiteList = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {
				"name": "v1",
				"expires": "3000-01-02 15:04"
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
		"target_url": "` + testHttpAny + `"
	}
}`

const versionedDefinition = `{
	"api_id": "9991",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"versions": {
			"v1": {"name": "v1"}
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
		"target_url": "` + testHttpAny + `"
	}
}`

const pathBasedDefinition = `{
	"api_id": "9992",
	"auth": {
		"use_param": true,
		"auth_header_name": "authorization"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"default": {
				"name": "default"
			}
		}
	},
	"proxy": {
		"listen_path": "/pathBased/",
		"target_url": "` + testHttpGet + `"
	}
}`

const extendedPathGatewaySetup = `{
	"api_id": "1",
	"definition": {
		"location": "header",
		"key": "version"
	},
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {
				"name": "v1",
				"use_extended_paths": true,
				"extended_paths": {
					"ignored": [
						{
							"path": "/v1/ignored/noregex",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
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
							"path": "/v1/allowed/whitelist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
									"headers": {
										"x-tyk-override-test": "tyk-override",
										"x-tyk-override-test-2": "tyk-override-2"
									}
								}
							}
						},
						{
							"path": "/v1/allowed/whitelist/reply/{id}",
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
							"path": "/v1/allowed/whitelist/{id}",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
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
							"path": "/v1/disallowed/blacklist/literal",
							"method_actions": {
								"GET": {
									"action": "no_action",
									"code": 200,
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
		"target_url": "` + testHttpAny + `"
	}
}`

func createSpecTest(t *testing.T, def string) *APISpec {
	spec := createDefinitionFromString(def)
	tname := t.Name()
	redisStore := storage.RedisCluster{KeyPrefix: tname + "-apikey."}
	healthStore := storage.RedisCluster{KeyPrefix: tname + "-apihealth."}
	orgStore := storage.RedisCluster{KeyPrefix: tname + "-orgKey."}
	spec.Init(redisStore, redisStore, healthStore, orgStore)
	return spec
}

func testKey(t *testing.T, name string) string {
	return fmt.Sprintf("%s-%s", t.Name(), name)
}

func testReqBody(t *testing.T, body interface{}) io.Reader {
	switch x := body.(type) {
	case []byte:
		return bytes.NewReader(x)
	case string:
		return strings.NewReader(x)
	case io.Reader:
		return x
	case nil:
		return nil
	default: // JSON objects (structs)
		bs, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(bs)
	}
}

func testReq(t *testing.T, method, urlStr string, body interface{}) *http.Request {
	return httptest.NewRequest(method, urlStr, testReqBody(t, body))
}

func withAuth(r *http.Request) *http.Request {
	// This is the default config secret
	r.Header.Set("x-tyk-authorization", "352d20ee67be67f6340b4c0605b044b7")
	return r
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
	req := testReq(t, "POST", uri, form.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "96869686969")
	req.Header.Set("version", "v1")

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	if recorder.Code != 200 {
		t.Error("Initial request failed with non-200 code: \n", recorder.Code)
	}
}

func TestVersioningRequestFail(t *testing.T) {
	spec := createSpecTest(t, versionedDefinition)
	session := createVersionedSession()
	session.AccessRights = map[string]user.AccessDefinition{"9991": {APIName: "Tyk Test API", APIID: "9991", Versions: []string{"v2"}}}

	// no version allowed
	spec.SessionManager.UpdateSession("zz1234", session, 60)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "zz1234")
	req.Header.Set("version", "v1")

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
	req := testReq(t, "GET", uri, nil)
	// No auth information, it's an ignored path!

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
	req := testReq(t, "GET", uri, nil)
	req.Header.Set("authorization", keyId)

	chain := getChain(spec)
	chain.ServeHTTP(recorder, req)

	body := recorder.Body.String()
	if body != "flump" {
		t.Error("Request body is incorrect! Is: ", body)
	}
}

func TestQuota(t *testing.T) {
	spec := createSpecTest(t, nonExpiringDefNoWhiteList)
	session := createQuotaSession()
	keyId := testKey(t, "key")
	spec.SessionManager.UpdateSession(keyId, session, 60)
	defer spec.SessionManager.ResetQuota(keyId, session)

	recorder := httptest.NewRecorder()
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", keyId)

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
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "ert1234ert")

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
	req := testReq(t, "GET", "/", nil)
	req.Header.Set("authorization", "dfgjg345316ertdg")

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
	body         interface{}

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

		ln, _ = net.Listen("tcp", "127.0.0.1:0")

		if separateControlPort {
			cln, _ = net.Listen("tcp", "127.0.0.1:0")

			_, port, _ := net.SplitHostPort(cln.Addr().String())
			config.Global.ControlAPIPort, _ = strconv.Atoi(port)
		} else {
			config.Global.ControlAPIPort = 0
		}

		config.Global.HttpServerOptions.OverrideDefaults = m.overrideDefaults

		// Ensure that no local API's installed
		os.RemoveAll(config.Global.AppPath)

		var err error
		config.Global.AppPath, err = ioutil.TempDir("", "tyk-test-")
		if err != nil {
			panic(err)
		}

		setupGlobals()
		// This is emulate calling start()
		// But this lines is the only thing needed for this tests
		if config.Global.ControlAPIPort == 0 {
			loadAPIEndpoints(mainRouter)
		}

		if m.goagain {
			listen(ln, cln, nil)
		} else {
			listen(ln, cln, fmt.Errorf("Without goagain"))
		}

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

			bodyReader := testReqBody(t, tc.body)
			req, err := http.NewRequest(tc.method, baseUrl+tc.path, bodyReader)
			if err != nil {
				t.Error(err)
				continue
			}

			if tc.adminAuth {
				req = withAuth(req)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != tc.code {
				t.Errorf("[%d]%s%s %s Status %d, want %d", ti, tPrefix, tc.method, tc.path, resp.StatusCode, tc.code)
			}
		}

		ln.Close()

		if cln != nil {
			cln.Close()
		}
	}
}

const sampleAPI = `{
	"api_id": "test",
	"use_keyless": true,
	"definition": {
		"location": "header",
		"key": "version"
	},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"proxy": {
		"listen_path": "/sample",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestListener(t *testing.T) {
	tests := []tykHttpTest{
		{method: "GET", path: "/sample", code: 404},
		{method: "GET", path: "/tyk/apis/", code: 403},
		{method: "GET", path: "/tyk/apis/", adminAuth: true, code: 200},
		{method: "GET", path: "/tyk/apis", code: 403},
		{method: "GET", path: "/tyk/apis", adminAuth: true, code: 200},
		{method: "POST", path: "/tyk/apis", body: sampleAPI, adminAuth: true, code: 200},
		// API definitions not reloaded yet
		{method: "GET", path: "/sample", code: 404},
		{method: "GET", path: "/tyk/reload/?block=true", adminAuth: true, code: 200},
		{method: "GET", path: "/sample", code: 200},
	}

	// have all needed reload ticks ready
	go func() {
		// two calls to testHttp, each loops over tests 4 times
		for i := 0; i < 2*4; i++ {
			reloadTick <- time.Time{}
		}
	}()
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

func TestHttpPprof(t *testing.T) {
	old := httpProfile
	defer func() { httpProfile = old }()

	testHttp(t, []tykHttpTest{
		{method: "GET", path: "/debug/pprof/", code: 404},
		{method: "GET", path: "/debug/pprof/", code: 404, controlRequest: true},
	}, true)
	*httpProfile = true
	doReload()
	testHttp(t, []tykHttpTest{
		{method: "GET", path: "/debug/pprof/", code: 404},
		{method: "GET", path: "/debug/pprof/", code: 200, controlRequest: true},
		{method: "GET", path: "/debug/pprof/heap", code: 200, controlRequest: true},
	}, true)
}

func TestManagementNodeRedisEvents(t *testing.T) {
	defer func() {
		config.Global.ManagementNode = false
	}()
	config.Global.ManagementNode = false
	msg := redis.Message{
		Data: []byte(`{"Command": "NoticeGatewayDRLNotification"}`),
	}
	shouldHandle := func(got NotificationCommand) {
		if want := NoticeGatewayDRLNotification; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, shouldHandle, nil)
	config.Global.ManagementNode = true
	notHandle := func(got NotificationCommand) {
		t.Fatalf("should have not handled redis event")
	}
	handleRedisEvent(msg, notHandle, nil)
}

const apiWithTykListenPathPrefix = `{
	"api_id": "test",
	"use_keyless": true,
	"version_data": {
		"not_versioned": true,
		"versions": {"v1": {"name": "v1"}}
	},
	"proxy": {
		"listen_path": "/tyk-foo/",
		"target_url": "` + testHttpAny + `"
	}
}`

func TestListenPathTykPrefix(t *testing.T) {
	tests := []tykHttpTest{
		{method: "POST", path: "/tyk/apis", body: apiWithTykListenPathPrefix, adminAuth: true, code: 200},
		{method: "GET", path: "/tyk-foo/", code: 404},
		{method: "GET", path: "/tyk/reload/?block=true", adminAuth: true, code: 200},
		{method: "GET", path: "/tyk-foo/", code: 200},
	}
	// have all needed reload ticks ready
	go func() {
		// one call to testHttp, each loops over tests 4 times
		for i := 0; i < 1*4; i++ {
			reloadTick <- time.Time{}
		}
	}()
	testHttp(t, tests, false)
}

func TestProxyUserAgent(t *testing.T) {
	spec := createSpecTest(t, sampleAPI)
	remote, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)

	tests := []struct {
		sent   interface{}
		wantRe string
	}{
		// none set; use our default
		{nil, `^Tyk/v\d+\.\d+\.\d+$`},
		// set but empty; let it through
		{"", `^$`},
		// set and not empty
		{"SomeAgent", `^SomeAgent$`},
	}
	for _, tc := range tests {
		rec := httptest.NewRecorder()
		req := testReq(t, "GET", "/sample", nil)
		if s, ok := tc.sent.(string); ok {
			req.Header.Set("User-Agent", s)
		}

		proxyHandler.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Error("Initial request failed with non-200 code: ", rec.Code)
			t.Error(rec.Body)
		}

		var resp testHttpResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatal("JSON decoding failed:", err)
		}

		rx := regexp.MustCompile(tc.wantRe)
		if got := resp.Headers["User-Agent"]; !rx.MatchString(got) {
			t.Errorf("Wanted agent to match %q, got %q\n", tc.wantRe, got)
		}
	}
}

func buildAndLoadAPI(apiGens ...func(spec *APISpec)) {
	oldPath := config.Global.AppPath
	config.Global.AppPath, _ = ioutil.TempDir("", "apps")
	defer func() {
		os.RemoveAll(config.Global.AppPath)
		config.Global.AppPath = oldPath
	}()

	for i, gen := range apiGens {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
		json.Unmarshal([]byte(sampleAPI), spec.APIDefinition)
		gen(spec)
		specBytes, _ := json.Marshal(spec)
		specFilePath := filepath.Join(config.Global.AppPath, spec.APIID+strconv.Itoa(i)+".json")
		if err := ioutil.WriteFile(specFilePath, specBytes, 0644); err != nil {
			panic(err)
		}
	}

	doReload()
}

func TestSkipUrlCleaning(t *testing.T) {
	// force ipv4 for now, to work around the docker bug affecting
	// Go 1.8 and ealier
	config.Global.ListenAddress = "127.0.0.1"

	config.Global.HttpServerOptions.OverrideDefaults = true
	config.Global.HttpServerOptions.SkipURLCleaning = true

	ln, _ := generateListener(0)
	baseURL := "http://" + ln.Addr().String()
	listen(ln, nil, nil)

	defer func() {
		config.Global.ListenAddress = ""
		config.Global.HttpServerOptions.OverrideDefaults = false
		config.Global.HttpServerOptions.SkipURLCleaning = false
		ln.Close()
	}()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = s.URL
	})

	resp, err := http.Get(baseURL + "/http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(body) != "/http://example.com" {
		t.Error("Should not strip URL", string(body))
	}
}

func TestMultiTargetProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	listen(ln, nil, nil)

	defer ln.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions = map[string]apidef.VersionInfo{
			"vdef": {Name: "vdef"},
			"vother": {
				Name:           "vother",
				OverrideTarget: testHttpAny + "/vother",
			},
		}
		spec.Proxy.ListenPath = "/"
	})
	tests := []struct {
		version, wantPath string
	}{
		{"vdef", "/"},
		{"vother", "/vother"},
	}

	for _, tc := range tests {
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("version", tc.version)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var testResp testHttpResponse
		if err := json.NewDecoder(resp.Body).Decode(&testResp); err != nil {
			t.Fatal(err)
		}
		if testResp.Url != tc.wantPath {
			t.Fatalf("wanted path %s, got %s", tc.wantPath, testResp.Url)
		}
	}
}
