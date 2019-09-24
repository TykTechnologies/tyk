package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"

	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/websocket"
	proxyproto "github.com/pires/go-proxyproto"
	msgpack "gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

const defaultListenPort = 8080

func TestMain(m *testing.M) {
	os.Exit(InitTestMain(context.Background(), m))
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

func TestAA(t *testing.T) {
	ts := StartTest()

	ts.Start()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	ts.Run(t, []test.TestCase{
		{Code: 200},
	}...)

}

type tykErrorResponse struct {
	Error string
}

func testKey(testName string, name string) string {
	return fmt.Sprintf("%s-%s", testName, name)
}

func TestParambasedAuth(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Auth.UseParam = true
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	key := CreateSession(func(s *user.SessionState) {
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

func TestStripPathWithURLRewrite(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	defer ResetTestConfig()

	t.Run("rewrite URL containing listen path", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			version := spec.VersionData.Versions["v1"]
			json.Unmarshal([]byte(`{
                "use_extended_paths": true,
                "extended_paths": {
                        "url_rewrites": [{
                                "path": "/anything/",
                                "match_pattern": "/anything/(.*)",
                                "method": "GET",
				"rewrite_to":"/something/$1"
                        }]
                }
            }`), &version)
			spec.VersionData.Versions["v1"] = version
			spec.Proxy.ListenPath = "/myapi/"
			spec.Proxy.StripListenPath = true

		})

		ts.Run(t, []test.TestCase{
			{Path: "/myapi/anything/a/myapi/b/c", BodyMatch: `"Url":"/something/a/myapi/b/c"`},
		}...)
	})
}

func TestSkipTargetPassEscapingOff(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	defer ResetTestConfig()

	t.Run("With escaping, default", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val`},
		}...)
	})

	t.Run("Without escaping", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/(abc,xyz)?arg=val"`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
		}...)
	})
}

func TestSkipTargetPassEscapingOffWithSkipURLCleaningTrue(t *testing.T) {
	globalConf := config.Global()
	globalConf.HttpServerOptions.OverrideDefaults = true
	globalConf.HttpServerOptions.SkipURLCleaning = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	// here we expect that test gateway will be sending to test upstream requests with not cleaned URI
	// so test upstream shouldn't reply with 301 and process them as well
	prevSkipClean := defaultTestConfig.HttpServerOptions.OverrideDefaults &&
		defaultTestConfig.HttpServerOptions.SkipURLCleaning
	testServerRouter.SkipClean(true)
	defer testServerRouter.SkipClean(prevSkipClean)

	ts := StartTest()
	defer ts.Close()

	t.Run("With escaping, default", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, default", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := config.Global()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/(abc,xyz)?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com?arg=val`},
		}...)
	})

}

func TestQuota(t *testing.T) {
	ts := StartTest()
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

	BuildAndLoadAPI(func(spec *APISpec) {
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
	keyID = CreateSession(func(s *user.SessionState) {
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
	ts := StartTest(TestConfig{
		Delay: 20 * time.Millisecond,
	})
	defer ts.Close()
	base := config.Global()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	// Cleanup before test
	// let records to to be sent
	time.Sleep(recordsBufferFlushInterval + 50)
	analytics.Store.GetAndDeleteSet(analyticsKeyName)

	t.Run("Log errors", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Path: "/", Code: 401},
			{Path: "/", Code: 401},
		}...)

		// let records to to be sent
		time.Sleep(recordsBufferFlushInterval + 50)

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
		key := CreateSession()

		authHeaders := map[string]string{
			"authorization": key,
		}

		ts.Run(t, test.TestCase{
			Path: "/", Headers: authHeaders, Code: 200,
		})

		// let records to to be sent
		time.Sleep(recordsBufferFlushInterval + 50)

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

	t.Run("Detailed analytics", func(t *testing.T) {
		defer func() {
			config.SetGlobal(base)
		}()
		globalConf := config.Global()
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
		})

		key := CreateSession()

		authHeaders := map[string]string{
			"authorization": key,
		}

		ts.Run(t, test.TestCase{
			Path: "/", Headers: authHeaders, Code: 200,
		})

		// let records to to be sent
		time.Sleep(recordsBufferFlushInterval + 50)

		results := analytics.Store.GetAndDeleteSet(analyticsKeyName)
		if len(results) != 1 {
			t.Error("Should return 1 record: ", len(results))
		}

		var record AnalyticsRecord
		msgpack.Unmarshal(results[0].([]byte), &record)
		if record.ResponseCode != 200 {
			t.Error("Analytics record do not match", record)
		}

		if record.RawRequest == "" {
			t.Error("Detailed request info not found", record)
		}

		if record.RawResponse == "" {
			t.Error("Detailed response info not found", record)
		}
	})

	t.Run("Detailed analytics with cache", func(t *testing.T) {
		defer func() {
			config.SetGlobal(base)
		}()
		globalConf := config.Global()
		globalConf.AnalyticsConfig.EnableDetailedRecording = true
		config.SetGlobal(globalConf)

		BuildAndLoadAPI(func(spec *APISpec) {
			spec.UseKeylessAccess = false
			spec.Proxy.ListenPath = "/"
			spec.CacheOptions = apidef.CacheOptions{
				CacheTimeout:         120,
				EnableCache:          true,
				CacheAllSafeRequests: true,
			}
		})

		key := CreateSession()

		authHeaders := map[string]string{
			"authorization": key,
		}

		ts.Run(t, []test.TestCase{
			{Path: "/", Headers: authHeaders, Code: 200},
			{Path: "/", Headers: authHeaders, Code: 200},
		}...)

		// let records to to be sent
		time.Sleep(recordsBufferFlushInterval + 50)

		results := analytics.Store.GetAndDeleteSet(analyticsKeyName)
		if len(results) != 2 {
			t.Fatal("Should return 1 record: ", len(results))
		}

		// Take second cached request
		var record AnalyticsRecord
		msgpack.Unmarshal(results[1].([]byte), &record)
		if record.ResponseCode != 200 {
			t.Error("Analytics record do not match", record)
		}

		if record.RawRequest == "" {
			t.Error("Detailed request info not found", record)
		}

		if record.RawResponse == "" {
			t.Error("Detailed response info not found", record)
		}
	})
}

func TestListener(t *testing.T) {
	// Trick to get spec JSON, without loading API
	// Specs will be reseted when we do `StartTest`
	specs := BuildAndLoadAPI()
	specJSON, _ := json.Marshal(specs[0].APIDefinition)
	listJSON := fmt.Sprintf("[%s]", string(specJSON))

	ts := StartTest()
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
			ReloadTick <- time.Time{}
		}
	}()

	ts.RunExt(t, tests...)
}

// Admin api located on separate port
func TestControlListener(t *testing.T) {
	ts := StartTest(TestConfig{
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
	DoReload()
	ts.RunExt(t, tests...)
}

func TestHttpPprof(t *testing.T) {
	old := cli.HTTPProfile
	defer func() { cli.HTTPProfile = old }()

	ts := StartTest(TestConfig{
		sepatateControlAPI: true,
	})

	ts.Run(t, []test.TestCase{
		{Path: "/debug/pprof/", Code: 404},
		{Path: "/debug/pprof/", Code: 404, ControlRequest: true},
	}...)
	ts.Close()

	*cli.HTTPProfile = true

	ts.Start()
	ts.Run(t, []test.TestCase{
		{Path: "/debug/pprof/", Code: 404},
		{Path: "/debug/pprof/", Code: 200, ControlRequest: true},
		{Path: "/debug/pprof/heap", Code: 200, ControlRequest: true},
	}...)
	ts.Close()
}

func TestManagementNodeRedisEvents(t *testing.T) {
	defer ResetTestConfig()
	globalConf := config.Global()
	globalConf.ManagementNode = false
	config.SetGlobal(globalConf)
	msg := redis.Message{
		Data: []byte(`{"Command": "NoticeGatewayDRLNotification"}`),
	}
	shouldHandle := func(got NotificationCommand) {
		if want := NoticeGatewayDRLNotification; got != want {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	handleRedisEvent(msg, shouldHandle, nil)
	globalConf.ManagementNode = true
	config.SetGlobal(globalConf)
	notHandle := func(got NotificationCommand) {
		t.Fatalf("should have not handled redis event")
	}
	handleRedisEvent(msg, notHandle, nil)
}

func TestListenPathTykPrefix(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/tyk-foo/"
	})

	ts.Run(t, test.TestCase{
		Path: "/tyk-foo/",
		Code: 200,
	})
}

func TestReloadGoroutineLeakWithAsyncWrites(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	globalConf := config.Global()
	globalConf.UseAsyncSessionWrite = true
	globalConf.EnableJSVM = false
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	specs := BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	before := runtime.NumGoroutine()

	LoadAPI(specs...) // just doing DoReload() doesn't load anything as BuildAndLoadAPI cleans up folder with API specs

	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()

	if before < after {
		t.Errorf("Goroutine leak, was: %d, after reload: %d", before, after)
	}
}

func TestReloadGoroutineLeakWithCircuitBreaker(t *testing.T) {
	t.Skip("gernest: proxying has changed need to rethink about how to test this")
	ts := StartTest()
	defer ts.Close()

	globalConf := config.Global()
	globalConf.EnableJSVM = false
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	specs := BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		UpdateAPIVersion(spec, "v1", func(version *apidef.VersionInfo) {
			version.ExtendedPaths = apidef.ExtendedPathsSet{
				CircuitBreaker: []apidef.CircuitBreakerMeta{
					{
						Path:                 "/",
						Method:               http.MethodGet,
						ThresholdPercent:     0.5,
						Samples:              5,
						ReturnToServiceAfter: 10,
					},
				},
			}
		})
	})

	before := runtime.NumGoroutine()

	LoadAPI(specs...) // just doing DoReload() doesn't load anything as BuildAndLoadAPI cleans up folder with API specs

	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()

	if before < after-1 { // -1 because there is one will be running until we fix circuitbreaker Subscribe() method
		t.Errorf("Goroutine leak, was: %d, after reload: %d", before, after)
	}
}

func listenProxyProto(ls net.Listener) error {
	pl := &proxyproto.Listener{Listener: ls}
	for {
		conn, err := pl.Accept()
		if err != nil {
			return err
		}
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			return err
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			return err
		}
	}
}

func TestProxyProtocol(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go listenProxyProto(l)
	ts := StartTest()
	defer ts.Close()
	rp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(rp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	EnablePort(p, "tcp")
	defer ResetTestConfig()

	proxyAddr := rp.Addr().String()
	rp.Close()
	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Protocol = "tcp"
		spec.EnableProxyProtocol = true
		spec.ListenPort = p
		spec.Proxy.TargetURL = l.Addr().String()
	})

	// we want to check if the gateway started listening on the tcp port.
	ls, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("expected the proxy to listen on address %s", proxyAddr)
	}
	defer ls.Close()
	ls.Write([]byte("ping"))
	recv := make([]byte, 4)
	_, err = ls.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("pong")) {
		t.Fatalf("bad: %v", recv)
	}
}

func TestProxyUserAgent(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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
	globalConf := config.Global()
	globalConf.HttpServerOptions.OverrideDefaults = true
	globalConf.HttpServerOptions.SkipURLCleaning = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer s.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = s.URL
	})

	ts.Run(t, test.TestCase{
		Path: "/http://example.com", BodyMatch: "/http://example.com", Code: 200,
	})
}

func TestMultiTargetProxy(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.VersionData.NotVersioned = false
		spec.VersionData.Versions = map[string]apidef.VersionInfo{
			"vdef": {Name: "vdef"},
			"vother": {
				Name:           "vother",
				OverrideTarget: TestHttpAny + "/vother",
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
		globalConf := config.Global()
		globalConf.EnableCustomDomains = true
		config.SetGlobal(globalConf)
		defer ResetTestConfig()

		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "host1"
				spec.Proxy.ListenPath = "/with_domain"
			},
			func(spec *APISpec) {
				spec.Domain = ""
				spec.Proxy.ListenPath = "/without_domain"
			},
		)

		ts.Run(t, []test.TestCase{
			{Code: 200, Path: "/with_domain", Domain: "host1"},
			{Code: 404, Path: "/with_domain"},
			{Code: 200, Path: "/without_domain"},
			{Code: 200, Path: "/tyk/keys", AdminAuth: true},
		}...)
	})

	t.Run("Without custom domain support", func(t *testing.T) {
		ts := StartTest()
		defer ts.Close()

		BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "host1.local."
				spec.Proxy.ListenPath = "/"
			},
			func(spec *APISpec) {
				spec.Domain = ""
				spec.Proxy.ListenPath = "/"
			},
		)

		ts.Run(t, []test.TestCase{
			{Code: 200, Path: "/with_domain", Domain: "host1"},
			{Code: 200, Path: "/with_domain"},
			{Code: 200, Path: "/without_domain"},
			{Code: 200, Path: "/tyk/keys", AdminAuth: true},
		}...)
	})
}

func TestHelloHealthcheck(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	t.Run("Without APIs", func(t *testing.T) {
		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/hello", Code: 200},
		}...)
	})

	t.Run("With APIs", func(t *testing.T) {
		BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/sample"
		})

		ts.Run(t, []test.TestCase{
			{Method: "GET", Path: "/hello", Code: 200},
			{Method: "GET", Path: "/sample/hello", Code: 200},
		}...)
	})
}

func TestCacheAllSafeRequests(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-"}
	defer cache.DeleteScanMatch("*")

	BuildAndLoadAPI(func(spec *APISpec) {
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

func TestCachePostRequest(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-"}
	defer cache.DeleteScanMatch("*")

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: false,
		}

		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			json.Unmarshal([]byte(`[{
						"method":"POST",
						"path":"/",
						"cache_key_regex":"\"id\":[^,]*"
					}
                                ]`), &v.ExtendedPaths.AdvanceCacheConfig)
		})

		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: "POST", Path: "/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: "POST", Path: "/", Data: "{\"id\":\"2\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		// if regex match returns nil, then request body is ignored while generating cache key
		{Method: "POST", Path: "/", Data: "{\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: "POST", Path: "/", Data: "{\"name\":\"test2\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
	}...)
}

func TestCacheEtag(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-"}
	defer cache.DeleteScanMatch("*")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", "12345")
		w.Write([]byte("body"))
	}))

	BuildAndLoadAPI(func(spec *APISpec) {
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

// func TestWebsocketsUpstreamUpgradeRequest(t *testing.T) {
// 	// setup spec and do test HTTP upgrade-request
// 	globalConf := config.Global()
// 	globalConf.HttpServerOptions.EnableWebSockets = true
// 	config.SetGlobal(globalConf)
// 	defer ResetTestConfig()

// 	ts := StartTest()
// 	defer ts.Close()

// 	BuildAndLoadAPI(func(spec *APISpec) {
// 		spec.Proxy.ListenPath = "/"
// 	})

// 	ts.Run(t, test.TestCase{
// 		Path: "/ws",
// 		Headers: map[string]string{
// 			"Connection":            "Upgrade",
// 			"Upgrade":               "websocket",
// 			"Sec-Websocket-Version": "13",
// 			"Sec-Websocket-Key":     "abc",
// 		},
// 		Code: http.StatusSwitchingProtocols,
// 	})
// }

func TestWebsocketsSeveralOpenClose(t *testing.T) {
	globalConf := config.Global()
	globalConf.HttpServerOptions.EnableWebSockets = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
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

func TestWebsocketsAndHTTPEndpointMatch(t *testing.T) {
	globalConf := config.Global()
	globalConf.HttpServerOptions.EnableWebSockets = true
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	baseURL := strings.Replace(ts.URL, "http://", "ws://", -1)

	// connect to ws, send 1st message and check reply
	wsConn, _, err := websocket.DefaultDialer.Dial(baseURL+"/ws", nil)
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}
	err = wsConn.WriteMessage(websocket.BinaryMessage, []byte("test message 1"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 1" {
		t.Error("Unexpected reply:", string(p))
	}

	// make 1st http request
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/abc",
		Code:   http.StatusOK,
	})

	// send second WS connection upgrade request
	// connect to ws, send 1st message and check reply
	wsConn2, _, err := websocket.DefaultDialer.Dial(baseURL+"/ws", nil)
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}
	err = wsConn2.WriteMessage(websocket.BinaryMessage, []byte("test message 1 to ws 2"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = wsConn2.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 1 to ws 2" {
		t.Error("Unexpected reply:", string(p))
	}
	wsConn2.Close()

	// send second message to WS and check reply
	err = wsConn.WriteMessage(websocket.BinaryMessage, []byte("test message 2"))
	if err != nil {
		t.Fatalf("cannot write message: %v", err)
	}
	_, p, err = wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("cannot read message: %v", err)
	}
	if string(p) != "reply to message: test message 2" {
		t.Error("Unexpected reply:", string(p))
	}

	// make 2nd http request
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/abc",
		Code:   http.StatusOK,
	})

	wsConn.Close()

	// make 3d http request after closing WS connection
	ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/abc",
		Code:   http.StatusOK,
	})
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
	ts := StartTest()
	defer ts.Close()
	defer ResetTestConfig()

	t.Run("Should use same connection", func(t *testing.T) {
		// set keep alive option
		globalConf := config.Global()
		globalConf.ProxyCloseConnections = false
		config.SetGlobal(globalConf)

		// Allow 1 connection with 3 reads
		upstream := createTestUptream(t, 1, 3)
		defer upstream.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
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
		globalConf := config.Global()
		globalConf.ProxyCloseConnections = true
		config.SetGlobal(globalConf)

		// Allow 3 connections with 1 read
		upstream := createTestUptream(t, 3, 1)
		defer upstream.Close()

		BuildAndLoadAPI(func(spec *APISpec) {
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
		globalConf := config.Global()
		globalConf.ProxyCloseConnections = false
		globalConf.MaxConnTime = 1
		config.SetGlobal(globalConf)

		// Allow 2 connection with 2 reads
		upstream := createTestUptream(t, 2, 2)
		defer upstream.Close()

		spec := BuildAndLoadAPI(func(spec *APISpec) {
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

// TestRateLimitForAPIAndRateLimitAndQuotaCheck ensures that the Rate Limit for the key is applied before the rate limit
// for the API. Meaning that a single token cannot reduce service availability for other tokens by simply going over the
// API's global rate limit.
func TestRateLimitForAPIAndRateLimitAndQuotaCheck(t *testing.T) {
	defer ResetTestConfig()
	ts := StartTest()
	defer ts.Close()

	globalCfg := config.Global()
	globalCfg.EnableNonTransactionalRateLimiter = false
	globalCfg.EnableSentinelRateLimiter = true
	config.SetGlobal(globalCfg)

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID += "_" + time.Now().String()
		spec.UseKeylessAccess = false
		spec.DisableRateLimit = false
		spec.OrgID = "default"
		spec.GlobalRateLimit = apidef.GlobalRateLimit{
			Rate: 2,
			Per:  60,
		}
		spec.Proxy.ListenPath = "/"
	})

	sess1token := CreateSession(func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})
	defer FallbackKeySesionManager.RemoveSession(sess1token, false)

	sess2token := CreateSession(func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})
	defer FallbackKeySesionManager.RemoveSession(sess2token, false)

	ts.Run(t, []test.TestCase{
		{Headers: map[string]string{"Authorization": sess1token}, Code: http.StatusOK, Path: "/", Delay: 100 * time.Millisecond},
		{Headers: map[string]string{"Authorization": sess1token}, Code: http.StatusTooManyRequests, Path: "/"},
		{Headers: map[string]string{"Authorization": sess2token}, Code: http.StatusOK, Path: "/", Delay: 100 * time.Millisecond},
		{Headers: map[string]string{"Authorization": sess2token}, Code: http.StatusTooManyRequests, Path: "/"},
	}...)
}

func TestTracing(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	prepareStorage()
	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
	})[0]

	keyID := CreateSession(func(s *user.SessionState) {})
	authHeaders := map[string][]string{"Authorization": {keyID}}

	ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/tyk/debug", AdminAuth: true, Code: 405},
		{Method: "POST", Path: "/tyk/debug", AdminAuth: true, Code: 400, BodyMatch: "Request malformed"},
		{Method: "POST", Path: "/tyk/debug", Data: `{}`, AdminAuth: true, Code: 400, BodyMatch: "Spec field is missing"},
		{Method: "POST", Path: "/tyk/debug", Data: `{"Spec": {}}`, AdminAuth: true, Code: 400, BodyMatch: "Request field is missing"},
		{Method: "POST", Path: "/tyk/debug", Data: `{"Spec": {}, "Request": {}}`, AdminAuth: true, Code: 400, BodyMatch: "Spec not valid, skipped!"},
		{Method: "POST", Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition, Request: &traceHttpRequest{Method: "GET", Path: "/"}}, AdminAuth: true, Code: 200, BodyMatch: `401 Unauthorized`},
		{Method: "POST", Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition, Request: &traceHttpRequest{Path: "/", Headers: authHeaders}}, AdminAuth: true, Code: 200, BodyMatch: `200 OK`},
	}...)
}

func TestBrokenClients(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	defer ResetTestConfig()

	globalConf := config.Global()
	globalConf.ProxyDefaultTimeout = 1
	config.SetGlobal(globalConf)

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.EnforcedTimeoutEnabled = true
	})

	buf := make([]byte, 1024)

	t.Run("Valid client", func(t *testing.T) {
		conn, _ := net.DialTimeout("tcp", mainProxy().listener.Addr().String(), 0)
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		conn.Read(buf)

		if string(buf[:12]) != "HTTP/1.1 200" {
			t.Error("Invalid server response:", string(buf))
		}
	})

	t.Run("Invalid client: close without read", func(t *testing.T) {
		time.Sleep(recordsBufferFlushInterval + 50*time.Millisecond)
		analytics.Store.GetAndDeleteSet(analyticsKeyName)

		conn, _ := net.DialTimeout("tcp", mainProxy().listener.Addr().String(), 0)
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		conn.Close()
		//conn.Read(buf)

		time.Sleep(recordsBufferFlushInterval + 50*time.Millisecond)
		results := analytics.Store.GetAndDeleteSet(analyticsKeyName)

		var record AnalyticsRecord
		msgpack.Unmarshal(results[0].([]byte), &record)
		if record.ResponseCode != 499 {
			t.Fatal("Analytics record do not match:", record)
		}
	})
}

func TestStripRegex(t *testing.T) {
	sample := []struct {
		strip  string
		path   string
		expect string
		vars   map[string]string
	}{
		{
			strip:  "/base",
			path:   "/base/path",
			expect: "/path",
			vars:   map[string]string{},
		},
		{
			strip:  "/base/{key}",
			path:   "/base/path/path",
			expect: "/path",
			vars: map[string]string{
				"key": "path",
			},
		},
		{
			strip:  "/taihoe-test/{test:[\\w\\d]+}/id/",
			path:   "/taihoe-test/asdas234234dad/id/v1/get",
			expect: "v1/get",
			vars: map[string]string{
				"test": "asdas234234dad",
			},
		},
	}
	for _, v := range sample {
		got := stripListenPath(v.strip, v.path, v.vars)
		if got != v.expect {
			t.Errorf("expected %s got %s", v.expect, got)
		}
	}
}
