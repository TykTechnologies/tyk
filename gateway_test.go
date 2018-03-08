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
var testServerRouter *mux.Router

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
	testServerRouter = testHttpHandler()
	testServer := &http.Server{
		Addr:           testHttpListen,
		Handler:        testServerRouter,
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

	purgeTicker = make(chan time.Time)
	rpcPurgeTicker = make(chan time.Time)

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

func testKey(t testing.TB, name string) string {
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

func TestSkipTargetPassEscapingOff(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()
	defer resetTestConfig()

	t.Run("With escaping, default", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val`},
		}...)
	})

	t.Run("Without escaping", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/(abc,xyz)?arg=val"`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
		}...)
	})
}

func TestSkipTargetPassEscapingOffWithSkipURLCleaningTrue(t *testing.T) {
	config.Global.HttpServerOptions.OverrideDefaults = true
	config.Global.HttpServerOptions.SkipURLCleaning = true
	defer resetTestConfig()

	// here we expect that test gateway will be sending to test upstream requests with not cleaned URI
	// so test upstream shouldn't reply with 301 and process them as well
	prevSkipClean := defaultTestConfig.HttpServerOptions.OverrideDefaults &&
		defaultTestConfig.HttpServerOptions.SkipURLCleaning
	testServerRouter.SkipClean(true)
	defer testServerRouter.SkipClean(prevSkipClean)

	ts := newTykTestServer()
	defer ts.Close()

	t.Run("With escaping, default", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, default", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = false

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		config.Global.HttpServerOptions.SkipTargetPathEscaping = true

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = testHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
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
	// Trick to get spec JSON, without loading API
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

func TestHelloHealthcheck(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()

	t.Run("Without APIs", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/hello", Code: 200},
		}...)
	})

	t.Run("With APIs", func(t *testing.T) {
		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
		})

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/hello", Code: 200},
			{Method: "GET", Path: "/sample/hello", Code: 200},
		}...)
	})
}

func TestCacheAllSafeRequests(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-"}
	defer cache.DeleteScanMatch("*")

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
		{Method: "GET", Path: "/", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
	}...)
}

func TestCacheEtag(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-"}
	defer cache.DeleteScanMatch("*")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", "12345")
		w.Write([]byte("body"))
	}))

	buildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: true,
		}
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = upstream.URL
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}
	invalidEtag := map[string]string{"If-None-Match": "invalid"}
	validEtag := map[string]string{"If-None-Match": "12345"}

	ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/", HeadersNotMatch: headerCache, Delay: 100 * time.Millisecond},
		{Method: "GET", Path: "/", HeadersMatch: headerCache, BodyMatch: "body"},
		{Method: "GET", Path: "/", Headers: invalidEtag, HeadersMatch: headerCache, BodyMatch: "body"},
		{Method: "GET", Path: "/", Headers: validEtag, HeadersMatch: headerCache, BodyNotMatch: "body"},
	}...)
}

func TestWebsocketsUpstreamUpgradeRequest(t *testing.T) {
	// setup spec and do test HTTP upgrade-request
	config.Global.HttpServerOptions.EnableWebSockets = true
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	ts.Run(t, test.TestCase{
		Path: "/ws",
		Headers: map[string]string{
			"Connection":            "Upgrade",
			"Upgrade":               "websocket",
			"Sec-Websocket-Version": "13",
			"Sec-Websocket-Key":     "abc",
		},
		Code: http.StatusSwitchingProtocols,
	})
}

func TestConcurrencyReloads(t *testing.T) {
	var wg sync.WaitGroup

	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			ts.Run(t, test.TestCase{Path: "/sample", Code: 200})
			wg.Done()
		}()
	}

	for j := 0; j < 5; j++ {
		buildAndLoadAPI()
	}

	wg.Wait()
}

func TestWebsocketsSeveralOpenClose(t *testing.T) {
	config.Global.HttpServerOptions.EnableWebSockets = true
	defer resetTestConfig()

	ts := newTykTestServer()
	defer ts.Close()

	buildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	baseURL := strings.Replace(ts.URL, "http://", "ws://", -1)

	// connect 1st time, send and read message, close connection
	conn1, _, err := websocket.DefaultDialer.Dial(baseURL+"/ws", nil)
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}
	err = conn1.WriteMessage(websocket.BinaryMessage, []byte("test message 1"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err := conn1.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 1" {
		t.Error("Unexpected reply:", string(p))
	}
	conn1.Close()

	// connect 2nd time, send and read message, but don't close yet
	conn2, _, err := websocket.DefaultDialer.Dial(baseURL+"/ws", nil)
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}
	err = conn2.WriteMessage(websocket.BinaryMessage, []byte("test message 2"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = conn2.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 2" {
		t.Error("Unexpected reply:", string(p))
	}

	// connect 3d time having one connection already open before, send and read message
	conn3, _, err := websocket.DefaultDialer.Dial(baseURL+"/ws", nil)
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}
	err = conn3.WriteMessage(websocket.BinaryMessage, []byte("test message 3"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = conn3.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 3" {
		t.Error("Unexpected reply:", string(p))
	}

	// check that we still can interact via 2nd connection we did before
	err = conn2.WriteMessage(websocket.BinaryMessage, []byte("new test message 2"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = conn2.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: new test message 2" {
		t.Error("Unexpected reply:", string(p))
	}

	// check that we still can interact via 3d connection we did before
	err = conn3.WriteMessage(websocket.BinaryMessage, []byte("new test message 3"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = conn3.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: new test message 3" {
		t.Error("Unexpected reply:", string(p))
	}

	// clean up connections
	conn2.Close()
	conn3.Close()
}

func createTestUptream(t *testing.T, allowedConns int, readsPerConn int) net.Listener {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		conns := 0

		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conns++

			if conns > allowedConns {
				t.Fatal("Too many connections")
				conn.Close()
				return
			}

			reads := 0
			go func() {
				for {
					buf := make([]byte, 1024)
					conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
					_, err := conn.Read(buf)
					if err != nil {
						conn.Close()
						return
					}
					reads++

					if reads > readsPerConn {
						t.Error("Too many reads per conn")
						conn.Close()
						return
					}

					conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
					conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				}
			}()
		}
	}()

	return l
}

func TestKeepAliveConns(t *testing.T) {
	ts := newTykTestServer()
	defer ts.Close()
	defer resetTestConfig()

	t.Run("Should use same connection", func(t *testing.T) {
		// set keep alive option
		config.Global.CloseConnections = false

		// Allow 1 connection with 3 reads
		upstream := createTestUptream(t, 1, 3)
		defer upstream.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})

		ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
			{Code: 200},
		}...)
	})

	t.Run("Should use separate connection", func(t *testing.T) {
		config.Global.CloseConnections = true

		// Allow 3 connections with 1 read
		upstream := createTestUptream(t, 3, 1)
		defer upstream.Close()

		buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})

		ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
			{Code: 200},
		}...)
	})

	t.Run("Should respect max_conn_time", func(t *testing.T) {
		config.Global.CloseConnections = false
		// Allow 2 connection with 2 reads
		upstream := createTestUptream(t, 2, 2)
		defer upstream.Close()
		config.Global.MaxConnTime = 1

		spec := buildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})[0]

		ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
		}...)

		// Set in past to re-create transport
		spec.HTTPTransportCreated = time.Now().Add(-time.Minute)

		// Should be called in new connection
		// We already made 2 requests above, so 3th in same not allowed
		ts.Run(t, test.TestCase{Code: 200})
	})
}
