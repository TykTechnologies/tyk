package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
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

	// Used to store the test bundles:
	testMiddlewarePath, _ = ioutil.TempDir("", "tyk-middleware-path")
)

const defaultListenPort = 8080

var defaultTestConfig config.Config

func resetTestConfig() {
	configMu.Lock()
	defer configMu.Unlock()
	config.Global = defaultTestConfig
}

// simulate reloads in the background, i.e. writes to
// global variables that should not be accessed in a
// racy way like the policies and api specs maps.
func reloadSimulation() {
	for {
		policiesMu.Lock()
		policiesByID["_"] = user.Policy{}
		delete(policiesByID, "_")
		policiesMu.Unlock()
		apisMu.Lock()
		old := apiSpecs
		apiSpecs = append(apiSpecs, nil)
		apiSpecs = old
		apisByID["_"] = nil
		delete(apisByID, "_")
		apisMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
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

	// Enable coprocess and bundle downloader:
	config.Global.CoProcessOptions.EnableCoProcess = true
	config.Global.EnableBundleDownloader = true
	config.Global.BundleBaseURL = testHttpBundles
	config.Global.MiddlewarePath = testMiddlewarePath

	// force ipv4 for now, to work around the docker bug affecting
	// Go 1.8 and ealier
	config.Global.ListenAddress = "127.0.0.1"

	initDNSMock()

	CoProcessInit()

	afterConfSetup(&config.Global)

	defaultTestConfig = config.Global

	initialiseSystem()
	// Small part of start()
	loadAPIEndpoints(mainRouter)
	if analytics.GeoIPDB == nil {
		panic("GeoIPDB was not initialized")
	}

	go reloadLoop(reloadTick)
	go reloadQueueLoop()
	go reloadSimulation()

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

func createStandardSession() *user.SessionState {
	session := new(user.SessionState)
	session.Rate = 10000
	session.Allowance = session.Rate
	session.LastCheck = time.Now().Unix()
	session.Per = 60
	session.Expires = -1
	session.QuotaRenewalRate = 300 // 5 minutes
	session.QuotaRenews = time.Now().Unix() + 20
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

func TestParambasedAuth(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Auth.UseParam = true
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	key := createSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	form := url.Values{}
	form.Add("foo", "swiggetty")
	form.Add("bar", "swoggetty")
	form.Add("baz", "swoogetty")

	expectedBody := `"Form":{"authorization":"` + key + `","bar":"swoggetty","baz":"swoogetty","foo":"swiggetty"}`

	ts.Run(t, test.TestCase{
		Method:    "POST",
		Path:      "/?authorization=" + key,
		Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Data:      string(form.Encode()),
		Code:      200,
		BodyMatch: expectedBody,
	})
}

func TestQuota(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	var keyID string

	var webhookWG sync.WaitGroup
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tyk-Test-Header") != "Tyk v1.BANANA" {
			t.Error("Custom webhook header not set", r.Header)
		}

		var data map[string]string
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &data)

		if data["event"] != "QuotaExceeded" || data["message"] != "Key Quota Limit Exceeded" || data["key"] != keyID {
			t.Error("Webhook payload not match", data)
		}

		webhookWG.Done()
	}))
	defer webhook.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"

		version := spec.VersionData.Versions["v1"]
		json.Unmarshal([]byte(`{
			"use_extended_paths": true,
			"extended_paths": {
				"ignored":[{
					"path": "/get",
					"method_actions": {"GET": {"action": "no_action"}}
				}]
			}
		}`), &version)
		spec.VersionData.Versions["v1"] = version

		json.Unmarshal([]byte(`
		{ "events": { "QuotaExceeded":
			[{
				"handler_name":"eh_log_handler",
				"handler_meta": {
					"prefix": "LOG-HANDLER-PREFIX"
				}
			},
			{
				"handler_name":"eh_web_hook_handler",
				"handler_meta": {
					"method": "POST",
					"target_path": "`+webhook.URL+`",
					"template_path": "templates/default_webhook.json",
					"header_map": {"X-Tyk-Test-Header": "Tyk v1.BANANA"},
					"event_timeout": 10
				}
			}]
		}}`), &spec.EventHandlers)
	})

	// Create session with Quota = 2
	keyID = createSession(func(s *user.SessionState) {
		s.QuotaMax = 2
	})

	authHeaders := map[string]string{
		"authorization": keyID,
	}

	webhookWG.Add(1)
	ts.Run(t, []test.TestCase{
		{Path: "/", Headers: authHeaders, Code: 200},
		// Ignored path should not affect quota
		{Path: "/get", Headers: authHeaders, Code: 200},
		{Path: "/", Headers: authHeaders, Code: 200},
		{Path: "/", Headers: authHeaders, Code: 403, BodyMatch: `"error": "Quota exceeded"`},
		// Ignored path works without auth
		{Path: "/get", Code: 200},
	}...)
	webhookWG.Wait()
}

func TestAnalytics(t *testing.T) {
	ts := newTykTestServer(tykTestServerConfig{
		delay: 20 * time.Millisecond,
	})
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	// Cleanup before test
	analytics.Store.GetAndDeleteSet(analyticsKeyName)

	t.Run("Log errors", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Path: "/", Code: 401},
			{Path: "/", Code: 401},
		}...)

		results := analytics.Store.GetAndDeleteSet(analyticsKeyName)
		if len(results) != 2 {
			t.Error("Should return 2 record", len(results))
		}

		var record AnalyticsRecord
		msgpack.Unmarshal(results[0].([]byte), &record)
		if record.ResponseCode != 401 {
			t.Error("Analytics record do not match: ", record)
		}
	})

	t.Run("Log success", func(t *testing.T) {
		key := createSession()

		authHeaders := map[string]string{
			"authorization": key,
		}

		ts.Run(t, test.TestCase{
			Path: "/", Headers: authHeaders, Code: 200,
		})

		results := analytics.Store.GetAndDeleteSet(analyticsKeyName)
		if len(results) != 1 {
			t.Error("Should return 1 record: ", len(results))
		}

		var record AnalyticsRecord
		msgpack.Unmarshal(results[0].([]byte), &record)
		if record.ResponseCode != 200 {
			t.Error("Analytics record do not match", record)
		}
	})
}

func TestListener(t *testing.T) {
	// Trcik to get spec JSON, without loading API
	// Specs will be reseted when we do `newTykTestServer`
	specs := buildAndLoadAPI()
	specJSON, _ := json.Marshal(specs[0].APIDefinition)
	listJSON := fmt.Sprintf("[%s]", string(specJSON))

	ts := newTykTestServer()
	defer ts.Close()

	tests := []test.TestCase{
		// Cleanup before tests
		{Method: "DELETE", Path: "/tyk/apis/test", AdminAuth: true},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},

		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/apis/", Code: 403},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: "[]"},
		{Method: "GET", Path: "/tyk/apis", Code: 403},
		{Method: "GET", Path: "/tyk/apis", AdminAuth: true, Code: 200},
		{Method: "POST", Path: "/tyk/apis", Data: sampleAPI, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: "[]"},
		{Method: "POST", Path: "/tyk/apis/mismatch", AdminAuth: true, Code: 400},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 404},
		// API definitions not reloaded yet
		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 200, BodyMatch: string(specJSON)},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: listJSON},
		{Method: "GET", Path: "/sample", Code: 200},
		{Method: "GET", Path: "/samplefoo", Code: 200},
		{Method: "GET", Path: "/sample/", Code: 200},
		{Method: "GET", Path: "/sample/foo", Code: 200},
	}

	// have all needed reload ticks ready
	go func() {
		for i := 0; i < 4*4; i++ {
			reloadTick <- time.Time{}
		}
	}()

	ts.RunExt(t, tests...)
}

// Admin api located on separate port
func TestControlListener(t *testing.T) {
	ts := newTykTestServer(tykTestServerConfig{
		sepatateControlAPI: true,
	})
	defer ts.Close()

	tests := []test.TestCase{
		{Method: "GET", Path: "/", Code: 404},
		{Method: "GET", Path: "/tyk/apis", Code: 404},

		// Querying control API
		{Method: "GET", Path: "/", Code: 404, ControlRequest: true},
		{Method: "GET", Path: "/tyk/apis", Code: 403, ControlRequest: true},
		{Method: "GET", Path: "/tyk/apis/", Code: 200, AdminAuth: true, ControlRequest: true},
	}

	ts.RunExt(t, tests...)
	doReload()
	ts.RunExt(t, tests...)
}

func TestHttpPprof(t *testing.T) {
	old := httpProfile
	defer func() { httpProfile = old }()

	ts := newTykTestServer(tykTestServerConfig{
		sepatateControlAPI: true,
	})

	ts.Run(t, []test.TestCase{
		{Path: "/debug/pprof/", Code: 404},
		{Path: "/debug/pprof/", Code: 404, ControlRequest: true},
	}...)
	ts.Close()

	*httpProfile = true

	ts.Start()
	ts.Run(t, []test.TestCase{
		{Path: "/debug/pprof/", Code: 404},
		{Path: "/debug/pprof/", Code: 200, ControlRequest: true},
		{Path: "/debug/pprof/heap", Code: 200, ControlRequest: true},
	}...)
	ts.Close()
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

func TestListenPathTykPrefix(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/tyk-foo/"
	})

	ts.Run(t, test.TestCase{
		Path: "/tyk-foo/",
		Code: 200,
	})
}

func TestProxyUserAgent(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	ts.Run(t, []test.TestCase{
		{
			Headers:   map[string]string{"User-Agent": ""},
			BodyMatch: fmt.Sprintf(`"User-Agent":"%s"`, defaultUserAgent),
		},
		{
			Headers:   map[string]string{"User-Agent": "SomeAgent"},
			BodyMatch: `"User-Agent":"SomeAgent"`,
		},
	}...)
}

func TestSkipUrlCleaning(t *testing.T) {
	config.Global.HttpServerOptions.OverrideDefaults = true
	config.Global.HttpServerOptions.SkipURLCleaning = true
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer s.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = s.URL
	})

	ts.Run(t, test.TestCase{
		Path: "/http://example.com", BodyMatch: "/http://example.com", Code: 200,
	})
}

func TestMultiTargetProxy(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

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

	ts.Run(t, []test.TestCase{
		{
			Headers:   map[string]string{"version": "vdef"},
			JSONMatch: map[string]string{"Url": `"/"`},
			Code:      200,
		},
		{
			Headers:   map[string]string{"version": "vother"},
			JSONMatch: map[string]string{"Url": `"/vother"`},
			Code:      200,
		},
	}...)
}

func TestCustomDomain(t *testing.T) {
	t.Run("With custom domain support", func(t *testing.T) {
		config.Global.EnableCustomDomains = true
		defer func() {
			config.Global.EnableCustomDomains = false
		}()

		buildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "localhost"
			},
			func(spec *APISpec) {
				spec.Domain = ""
			},
		)
	})

	t.Run("Without custom domain support", func(t *testing.T) {
		buildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "localhost"
			},
			func(spec *APISpec) {
				spec.Domain = ""
			},
		)
	})
}

func TestWithCacheAllSafeRequests(t *testing.T) {
	ts := newTykTestServer(tykTestServerConfig{
		delay: 10 * time.Millisecond,
	})
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: true,
		}
		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/", HeadersNotMatch: headerCache},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
	}...)
}

func TestWebsocketsUpstream(t *testing.T) {
	// setup and run web socket upstream
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	wsHandler := func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Error("cannot upgrade:", err)
			http.Error(w, fmt.Sprintf("cannot upgrade: %v", err), http.StatusInternalServerError)
		}
		mt, p, err := conn.ReadMessage()
		if err != nil {
			t.Error("cannot read message:", err)
			return
		}
		conn.WriteMessage(mt, []byte("reply to message:"+string(p)))
	}
	wsServer := httptest.NewServer(http.HandlerFunc(wsHandler))
	defer wsServer.Close()
	u, _ := url.Parse(wsServer.URL)
	u.Scheme = "ws"
	targetUrl := u.String()

	// setup spec and do test HTTP upgrade-request
	config.Global.HttpServerOptions.EnableWebSockets = true
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = targetUrl
	})

	ts.Run(t, test.TestCase{
		Code: http.StatusSwitchingProtocols,
		Headers: map[string]string{
			"Connection":            "Upgrade",
			"Upgrade":               "websocket",
			"Sec-Websocket-Version": "13",
			"Sec-Websocket-Key":     "abc",
		},
	})
}
