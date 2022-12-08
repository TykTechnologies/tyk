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

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/websocket"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	msgpack "gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestMain(m *testing.M) {
	os.Exit(InitTestMain(context.Background(), m))
}

func testKey(testName string, name string) string {
	return fmt.Sprintf("%s-%s", testName, name)
}

func TestParambasedAuth(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Auth.UseParam = true
		spec.UseKeylessAccess = false
		spec.Proxy.ListenPath = "/"
	})

	key := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{"test": {
			APIID: "test", Versions: []string{"v1"},
		}}
	})

	form := url.Values{}
	form.Add("foo", "swiggetty")
	form.Add("bar", "swoggetty")
	form.Add("baz", "swoogetty")

	expectedBody := `"Form":{"authorization":"` + key + `","bar":"swoggetty","baz":"swoogetty","foo":"swiggetty"}`

	_, _ = ts.Run(t, test.TestCase{
		Method:    "POST",
		Path:      "/?authorization=" + key,
		Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Data:      string(form.Encode()),
		Code:      200,
		BodyMatch: expectedBody,
	})
}

func TestStripPathWithURLRewrite(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("rewrite URL containing listen path", func(t *testing.T) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/myapi/anything/a/myapi/b/c", BodyMatch: `"Url":"/something/a/myapi/b/c"`},
		}...)
	})
}

func TestSkipTargetPassEscapingOff(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("With escaping, default", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29\?arg=val`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29\?arg=val`},
		}...)
	})

	t.Run("Without escaping", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/(abc,xyz)?arg=val", BodyMatch: `"Url":"/\(abc,xyz\)\?arg=val"`},
			{Path: "/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/%28abc,xyz%29\?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/\(abc,xyz\)\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/\(abc,xyz\)\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
		}...)
	})
}

func TestSkipTargetPassEscapingOffWithSkipURLCleaningTrue(t *testing.T) {

	conf := func(c *config.Config) {
		c.HttpServerOptions.OverrideDefaults = true
		c.HttpServerOptions.SkipURLCleaning = true
	}
	ts := StartTest(conf)
	defer ts.Close()

	ts.TestServerRouter.SkipClean(true)

	t.Run("With escaping, default", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

	t.Run("Without escaping, default", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/abc/xyz/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/abc/xyz/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is OFF", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = false
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/\(abc,xyz\)\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/listen_me/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

	t.Run("With escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = false
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
			// change name to change checksum and reload
			spec.Name = t.Name()
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

	t.Run("Without escaping, listen path and target URL are set, StripListenPath is ON", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.HttpServerOptions.SkipTargetPathEscaping = true
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.StripListenPath = true
			spec.Proxy.ListenPath = "/listen_me"
			spec.Proxy.TargetURL = TestHttpAny + "/sent_to_me"
			// change name to change checksum and reload
			spec.Name = t.Name()
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/listen_me/(abc,xyz)?arg=val", BodyMatch: `"Url":"/sent_to_me/\(abc,xyz\)\?arg=val"`},
			{Path: "/listen_me/%28abc,xyz%29?arg=val", BodyMatch: `"Url":"/sent_to_me/%28abc,xyz%29\?arg=val"`},
			{Path: "/listen_me/http%3A%2F%2Ftest.com?arg=val", BodyMatch: `"Url":"/sent_to_me/http%3A%2F%2Ftest.com\?arg=val`},
		}...)
	})

}

func TestQuota(t *testing.T) {
	ts := StartTest(nil)
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

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
	keyID = CreateSession(ts.Gw, func(s *user.SessionState) {
		s.QuotaMax = 2
	})

	authHeaders := map[string]string{
		"authorization": keyID,
	}

	webhookWG.Add(1)
	_, _ = ts.Run(t, []test.TestCase{
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

func TestListener(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	ts.Gw.ReloadTestCase.StartTicker()
	defer ts.Gw.ReloadTestCase.StopTicker()
	tests := []test.TestCase{
		// Cleanup before tests
		{Method: "DELETE", Path: "/tyk/apis/test", AdminAuth: true},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},

		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/apis/", Code: 403},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `\[\]`},
		{Method: "GET", Path: "/tyk/apis", Code: 403},
		{Method: "GET", Path: "/tyk/apis", AdminAuth: true, Code: 200},
		{Method: "POST", Path: "/tyk/apis", Data: sampleAPI, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `\[\]`},
		{Method: "POST", Path: "/tyk/apis/mismatch", AdminAuth: true, Code: 400},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 404},
		// API definitions not reloaded yet
		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 200, BodyMatch: `^{.*"api_id":"test".*}`},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `^\[.*"api_id":"test".*\]`},
		{Method: "GET", Path: "/sample", Code: 200},
		{Method: "GET", Path: "/samplefoo", Code: 200},
		{Method: "GET", Path: "/sample/", Code: 200},
		{Method: "GET", Path: "/sample/foo", Code: 200},
	}

	ts.RunExt(t, tests...)
}

func TestListenerWithStrictRoutes(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.HttpServerOptions.EnableStrictRoutes = true
	})
	defer ts.Close()

	ts.Gw.ReloadTestCase.Enable()
	defer ts.Gw.ReloadTestCase.Disable()

	ts.Gw.ReloadTestCase.StartTicker()
	defer ts.Gw.ReloadTestCase.StopTicker()
	tests := []test.TestCase{
		// Cleanup before tests
		{Method: "DELETE", Path: "/tyk/apis/test", AdminAuth: true},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},

		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/apis/", Code: 403},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `\[\]`},
		{Method: "GET", Path: "/tyk/apis", Code: 403},
		{Method: "GET", Path: "/tyk/apis", AdminAuth: true, Code: 200},
		{Method: "POST", Path: "/tyk/apis", Data: sampleAPI, AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `\[\]`},
		{Method: "POST", Path: "/tyk/apis/mismatch", AdminAuth: true, Code: 400},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 404},
		// API definitions not reloaded yet
		{Method: "GET", Path: "/sample", Code: 404},
		{Method: "GET", Path: "/tyk/reload/?block=true", AdminAuth: true, Code: 200},
		{Method: "GET", Path: "/tyk/apis/test", AdminAuth: true, Code: 200, BodyMatch: `^{.*"api_id":"test".*}`},
		{Method: "GET", Path: "/tyk/apis/", AdminAuth: true, Code: 200, BodyMatch: `^\[.*"api_id":"test".*\]`},
		{Method: "GET", Path: "/sample", Code: 200},
		{Method: "GET", Path: "/samplefoo", Code: 404},
		{Method: "GET", Path: "/sample/", Code: 200},
		{Method: "GET", Path: "/sample/foo", Code: 200},
	}

	ts.RunExt(t, tests...)
}

// Admin api located on separate port
func TestControlListener(t *testing.T) {
	ts := StartTest(nil, TestConfig{
		SeparateControlAPI: true,
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
	ts.Gw.DoReload()
	ts.RunExt(t, tests...)

	// Moved here because globalGateway.DoReload overrides it
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/user-api"
		spec.UseKeylessAccess = true
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/user-api", Code: http.StatusOK},
		{Path: "/user-api", ControlRequest: true, Code: http.StatusNotFound},
	}...)
}

func TestHttpPprof(t *testing.T) {

	t.Run("HTTP Profile not active", func(t *testing.T) {
		conf := func(globalConf *config.Config) {
			globalConf.HTTPProfile = false
		}
		ts := StartTest(conf, TestConfig{
			SeparateControlAPI: true,
		})
		defer ts.Close()

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/debug/pprof/", Code: 404},
			{Path: "/debug/pprof/", Code: 404, ControlRequest: true},
		}...)
	})

	t.Run("HTTP Profile active", func(t *testing.T) {
		conf := func(globalConf *config.Config) {
			globalConf.HTTPProfile = true
		}
		ts := StartTest(conf, TestConfig{
			SeparateControlAPI: true,
		})
		defer ts.Close()

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/debug/pprof/", Code: 404},
			{Path: "/debug/pprof/", Code: 200, ControlRequest: true},
			{Path: "/debug/pprof/heap", Code: 200, ControlRequest: true},
		}...)
	})
}

func TestManagementNodeRedisEvents(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.ManagementNode = false
	ts.Gw.SetConfig(globalConf)

	t.Run("Without signing:", func(t *testing.T) {
		msg := redis.Message{
			Payload: `{"Command": "NoticeGatewayDRLNotification"}`,
		}

		callbackRun := false
		shouldHandle := func(got NotificationCommand) {
			callbackRun = true
			if want := NoticeGatewayDRLNotification; got != want {
				t.Fatalf("want %q, got %q", want, got)
			}
		}
		ts.Gw.handleRedisEvent(&msg, shouldHandle, nil)
		if !callbackRun {
			t.Fatalf("Should run callback")
		}
		globalConf.ManagementNode = true
		ts.Gw.SetConfig(globalConf)
		notHandle := func(got NotificationCommand) {
			t.Fatalf("should have not handled redis event")
		}
		ts.Gw.handleRedisEvent(msg, notHandle, nil)
	})

	t.Run("With signature", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.AllowInsecureConfigs = false
		ts.Gw.SetConfig(globalConf)

		n := Notification{
			Command: NoticeGroupReload,
			Payload: string("test"),
			Gw:      ts.Gw,
		}
		n.Sign()
		msg := redis.Message{}
		payload, _ := json.Marshal(n)
		msg.Payload = string(payload)

		callbackRun := false
		shouldHandle := func(got NotificationCommand) {
			callbackRun = true
			if want := NoticeGroupReload; got != want {
				t.Fatalf("want %q, got %q", want, got)
			}
		}

		ts.Gw.handleRedisEvent(&msg, shouldHandle, nil)
		if !callbackRun {
			t.Fatalf("Should run callback")
		}

		n.Signature = "wrong"
		payload, _ = json.Marshal(n)
		msg.Payload = string(payload)

		valid := false
		shouldFail := func(got NotificationCommand) {
			valid = true
		}
		ts.Gw.handleRedisEvent(&msg, shouldFail, nil)
		if valid {
			t.Fatalf("Should fail validation")
		}
	})
}

func TestListenPathTykPrefix(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/tyk-foo/"
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/tyk-foo/",
		Code: 200,
	})
}

func TestReloadGoroutineLeakWithTest(t *testing.T) {
	test.Flaky(t)

	before := runtime.NumGoroutine()

	ts := StartTest(nil)
	ts.Close()

	time.Sleep(time.Second)

	after := runtime.NumGoroutine()

	if before < after {
		t.Errorf("Goroutine leak, was: %d, after reload: %d", before, after)
	}
}

func TestReloadGoroutineLeakWithCircuitBreaker(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.EnableJSVM = false
	ts.Gw.SetConfig(globalConf)

	specs := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	ts.Gw.LoadAPI(specs...) // just doing globalGateway.DoReload() doesn't load anything as BuildAndLoadAPI cleans up folder with API specs

	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()

	if before < after {
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
	ts := StartTest(nil)
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
	ts.EnablePort(p, "tcp")

	proxyAddr := rp.Addr().String()
	rp.Close()
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
	})

	_, _ = ts.Run(t, []test.TestCase{
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
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HttpServerOptions.OverrideDefaults = true
	globalConf.HttpServerOptions.SkipURLCleaning = true
	ts.Gw.SetConfig(globalConf)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Path))
	}))
	defer s.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = s.URL
	})

	_, _ = ts.Run(t, test.TestCase{
		Path: "/http://example.com", BodyMatch: "/http://example.com", Code: 200,
	})
}

func TestMultiTargetProxy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	_, _ = ts.Run(t, []test.TestCase{
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
	ts := StartTest(nil)
	defer ts.Close()

	localClient := test.NewClientLocal()

	t.Run("With custom domain support", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.EnableCustomDomains = true
		ts.Gw.SetConfig(globalConf)
		defer ts.ResetTestConfig()

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "host1"
				spec.Proxy.ListenPath = "/with_domain"
			},
			func(spec *APISpec) {
				spec.Domain = ""
				spec.Proxy.ListenPath = "/without_domain"
			},
		)

		_, _ = ts.Run(t, []test.TestCase{
			{Client: localClient, Code: 200, Path: "/with_domain", Domain: "host1"},
			{Client: localClient, Code: 404, Path: "/with_domain"},
			{Client: localClient, Code: 200, Path: "/without_domain"},
			{Client: localClient, Code: 200, Path: "/tyk/keys", AdminAuth: true},
		}...)
	})

	t.Run("Without custom domain support", func(t *testing.T) {

		ts.Gw.BuildAndLoadAPI(
			func(spec *APISpec) {
				spec.Domain = "host1.local."
				spec.Proxy.ListenPath = "/"
			},
			func(spec *APISpec) {
				spec.Domain = ""
				spec.Proxy.ListenPath = "/"
			},
		)

		_, _ = ts.Run(t, []test.TestCase{
			{Client: localClient, Code: 200, Path: "/with_domain", Domain: "host1"},
			{Client: localClient, Code: 200, Path: "/with_domain"},
			{Client: localClient, Code: 200, Path: "/without_domain"},
			{Client: localClient, Code: 200, Path: "/tyk/keys", AdminAuth: true},
		}...)
	})
}

func TestGatewayHealthCheck(t *testing.T) {

	t.Run("control api port == listen port", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		t.Run("Without APIs", func(t *testing.T) {
			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/hello", BodyMatch: `"status":"pass"`, Code: http.StatusOK},
			}...)
		})

		t.Run("With API", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/sample"
			})

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/hello", BodyMatch: `"status":"pass"`, Code: http.StatusOK},
			}...)
		})
	})

	t.Run("control api port != listen port", func(t *testing.T) {
		ts := StartTest(nil, TestConfig{
			SeparateControlAPI: true,
		})
		defer ts.Close()

		t.Run("Without APIs", func(t *testing.T) {
			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/hello", Code: http.StatusNotFound},
				{ControlRequest: true, Path: "/hello", BodyMatch: `"status":"pass"`, Code: http.StatusOK},
			}...)
		})

		t.Run("With API", func(t *testing.T) {
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/sample"
			})

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/hello", Code: http.StatusNotFound},
				{ControlRequest: true, Path: "/hello", BodyMatch: `"status":"pass"`, Code: http.StatusOK},
			}...)
		})
	})
}

func TestCacheAllSafeRequests(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: true,
		}
		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "POST", Path: "/", HeadersNotMatch: headerCache},
		{Method: "GET", Path: "/", HeadersMatch: headerCache},
	}...)
}

func TestCacheAllSafeRequestsWithCachedHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")
	authorization := "authorization"
	tenant := "tenant-id"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: true,
			CacheByHeaders:       []string{authorization, tenant},
		}
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}
	sess1token := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})
	sess2token := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{authorization: sess1token}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{authorization: sess1token}, HeadersMatch: headerCache},
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{authorization: sess2token}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{tenant: "Some UUID"}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{tenant: "Some UUID"}, HeadersMatch: headerCache},
		{Method: http.MethodGet, Path: "/", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/", HeadersMatch: headerCache},
		{Method: http.MethodGet, Path: "/", Headers: map[string]string{tenant: "Some UUID", authorization: sess2token}, HeadersNotMatch: headerCache},
	}...)
}

func TestCacheWithAdvanceUrlRewrite(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		version := spec.VersionData.Versions["v1"]
		version.UseExtendedPaths = true
		version.ExtendedPaths = apidef.ExtendedPathsSet{
			URLRewrite: []apidef.URLRewriteMeta{
				{
					Path:         "/test",
					Method:       http.MethodGet,
					MatchPattern: "/test(.*)",
					Triggers: []apidef.RoutingTrigger{
						{
							On: "all",
							Options: apidef.RoutingTriggerOptions{
								HeaderMatches: map[string]apidef.StringRegexMap{
									"rewritePath": {
										MatchPattern: "newpath",
									},
								},
							},
							RewriteTo: "/newpath",
						},
					},
				},
			},
			Cached: []string{"/test"},
		}
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout: 120,
			EnableCache:  true,
		}
		spec.Proxy.ListenPath = "/"
		spec.VersionData.Versions["v1"] = version
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}
	matchHeaders := map[string]string{"rewritePath": "newpath"}
	randomheaders := map[string]string{"something": "abcd"}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodGet, Path: "/test", Headers: matchHeaders, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/test", Headers: matchHeaders, HeadersMatch: headerCache},
		//Even if trigger condition failed, as response is cached
		// will still get redirected response
		{Method: http.MethodGet, Path: "/test", Headers: randomheaders, HeadersMatch: headerCache, BodyMatch: `"Url":"/newpath"`},
		{Method: http.MethodPost, Path: "/test", HeadersNotMatch: headerCache},
		{Method: http.MethodGet, Path: "/test", HeadersMatch: headerCache},
	}...)
}

func TestCachePostRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")
	tenant := "tenant-id"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:         120,
			EnableCache:          true,
			CacheAllSafeRequests: false,
			CacheByHeaders:       []string{tenant},
		}

		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.AdvanceCacheConfig = []apidef.CacheMeta{
				{
					Method:        http.MethodPost,
					Path:          "/",
					CacheKeyRegex: "\"id\":[^,]*",
				},
			}
		})

		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPost, Path: "/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPost, Path: "/", Data: "{\"id\":\"2\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		// if regex match returns nil, then request body is ignored while generating cache key
		{Method: http.MethodPost, Path: "/", Data: "{\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPost, Path: "/", Data: "{\"name\":\"test2\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPost, Path: "/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPost, Path: "/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersMatch: headerCache},
	}...)
}

func TestAdvanceCachePutRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")
	tenant := "tenant-id"

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:           120,
			EnableCache:            true,
			CacheAllSafeRequests:   true,
			CacheOnlyResponseCodes: []int{404}, // should not influence because of AdvanceCacheConfig.CacheOnlyResponseCodes
			CacheByHeaders:         []string{tenant},
		}
		spec.Proxy.ListenPath = "/"

		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			err := json.Unmarshal([]byte(`[{
						"method":"PUT",
						"path":"/put/",
						"cache_key_regex":"\"id\":[^,]*",
						"cache_response_codes":[200]
					},{
						"method":"PATCH",
						"path":"/patch/",
						"cache_key_regex":"\"id\":[^,]*",
						"cache_response_codes":[200]
					},{
						"method":"DELETE",
						"path":"/delete/",
						"cache_response_codes":[200]
					},{
						"method":"PUT",
						"path":"/full-body-hash/",
						"cache_response_codes":[200],
						"cache_key_regex":".*"
					}
                                ]`), &v.ExtendedPaths.AdvanceCacheConfig)
			assert.NoError(t, err)
		})
		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPut, Path: "/put/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond}, // 0
		{Method: http.MethodPut, Path: "/put/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/put/", Data: "{\"id\":\"2\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		// if regex match returns nil, then request body is ignored while generating cache key
		{Method: http.MethodPut, Path: "/put/", Data: "{\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/put/", Data: "{\"name\":\"test2\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/put/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{"someheader": "someUUID"}, HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		// test when no body and no headers
		{Method: http.MethodPut, Path: "/put/", HeadersMatch: headerCache},
		// test CacheByHeaders change - header added
		{Method: http.MethodPut, Path: "/put/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/put/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersMatch: headerCache},

		// PATCH
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond}, // 10
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"id\":\"2\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		// if regex match returns nil, then request body is ignored while generating cache key
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"name\":\"test2\"}", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{"someheader": "someUUID"}, HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		// test when no body and no headers
		{Method: http.MethodPatch, Path: "/patch/", HeadersMatch: headerCache},
		// test CacheByHeaders change - header added
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPatch, Path: "/patch/", Data: "{\"name\":\"test2\"}", Headers: map[string]string{tenant: "someUUID"}, HeadersMatch: headerCache},

		// DELETE
		{Method: http.MethodDelete, Path: "/delete/", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodDelete, Path: "/delete/", HeadersMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodDelete, Path: "/delete/", Headers: map[string]string{tenant: "someUUID"}, HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond}, // 20
		{Method: http.MethodDelete, Path: "/delete/", Headers: map[string]string{tenant: "someUUID"}, HeadersMatch: headerCache},

		// Put with full body hash
		{Method: http.MethodPut, Path: "/full-body-hash/", Data: "{\"id\":\"1\",\"name\":\"test\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/full-body-hash/", Data: "{\"id\":\"1\",\"name\":\"test2\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/full-body-hash/", Data: "{\"id\":\"2\",\"name\":\"test2\"}", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodPut, Path: "/full-body-hash/", Data: "{\"id\":\"2\",\"name\":\"test2\"}", HeadersMatch: headerCache},
	}...)
}

func TestCacheAllSafeRequestsWithAdvancedCacheEndpoint(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.CacheOptions = apidef.CacheOptions{
			CacheTimeout:           120,
			EnableCache:            true,
			CacheAllSafeRequests:   true,
			CacheOnlyResponseCodes: []int{200}, // should not influence because of AdvanceCacheConfig.CacheOnlyResponseCodes
		}

		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			json.Unmarshal([]byte(`[{
						"method":"PUT",
						"path":"/",
						"cache_key_regex":"\"id\":[^,]*",
						"cache_response_codes":[404]
					}
                               ]`), &v.ExtendedPaths.AdvanceCacheConfig)
		})
		spec.Proxy.ListenPath = "/"
	})

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	_, _ = ts.Run(t, []test.TestCase{
		// Make sure CacheAllSafeRequests is working
		{Method: http.MethodGet, Path: "/", HeadersNotMatch: headerCache, Delay: 10 * time.Millisecond},
		{Method: http.MethodGet, Path: "/", HeadersMatch: headerCache},
	}...)
}

func TestCacheEtag(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
	defer cache.DeleteScanMatch("*")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", "12345")
		w.Write([]byte("body"))
	}))

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	_, _ = ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/", HeadersNotMatch: headerCache, Delay: 100 * time.Millisecond},
		{Method: "GET", Path: "/", HeadersMatch: headerCache, BodyMatch: "body"},
		{Method: "GET", Path: "/", Headers: invalidEtag, HeadersMatch: headerCache, BodyMatch: "body"},
		{Method: "GET", Path: "/", Headers: validEtag, HeadersMatch: headerCache, BodyNotMatch: "body"},
	}...)
}

func TestOldCachePlugin(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	api := BuildAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		UpdateAPIVersion(spec, "v1", func(version *apidef.VersionInfo) {
			version.UseExtendedPaths = true
			version.ExtendedPaths.Cached = []string{"/test"}
		})
		spec.CacheOptions = apidef.CacheOptions{
			EnableCache:  true,
			CacheTimeout: 120,
		}
	})[0]

	headerCache := map[string]string{"x-tyk-cached-response": "1"}

	check := func(t *testing.T) {
		cache := storage.RedisCluster{KeyPrefix: "cache-", RedisController: ts.Gw.RedisController}
		defer cache.DeleteScanMatch("*")

		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/test", HeadersNotMatch: headerCache, Code: http.StatusOK, Delay: 10 * time.Millisecond},
			{Path: "/test", HeadersMatch: headerCache, Code: http.StatusOK},
			{Path: "/anything", HeadersNotMatch: headerCache, Code: http.StatusOK, Delay: 10 * time.Millisecond},
			{Path: "/anything", HeadersNotMatch: headerCache, Code: http.StatusOK},
		}...)
	}

	check(t)

	t.Run("migration", func(t *testing.T) {
		_, err := api.Migrate()
		assert.NoError(t, err)

		check(t)
	})
}

func TestWebsocketsSeveralOpenClose(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HttpServerOptions.EnableWebSockets = true
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.HttpServerOptions.EnableWebSockets = true
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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
	_, _ = ts.Run(t, test.TestCase{
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
	_, _ = ts.Run(t, test.TestCase{
		Method: "GET",
		Path:   "/abc",
		Code:   http.StatusOK,
	})

	wsConn.Close()

	// make 3d http request after closing WS connection
	_, _ = ts.Run(t, test.TestCase{
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
				t.Error("Too many connections")
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
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("Should use same connection", func(t *testing.T) {
		// set keep alive option
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxyCloseConnections = false
		ts.Gw.SetConfig(globalConf)

		// Allow 1 connection with 3 reads
		upstream := createTestUptream(t, 1, 3)
		defer upstream.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
			{Code: 200},
		}...)
	})

	t.Run("Should use separate connection", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxyCloseConnections = true
		ts.Gw.SetConfig(globalConf)

		// Allow 3 connections with 1 read
		upstream := createTestUptream(t, 3, 1)
		defer upstream.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})

		_, _ = ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
			{Code: 200},
		}...)
	})

	t.Run("Should respect max_conn_time", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxyCloseConnections = false
		globalConf.MaxConnTime = 1
		ts.Gw.SetConfig(globalConf)

		// Allow 2 connection with 2 reads
		upstream := createTestUptream(t, 2, 2)
		defer upstream.Close()

		spec := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.Proxy.TargetURL = "http://" + upstream.Addr().String()
		})[0]

		_, _ = ts.Run(t, []test.TestCase{
			{Code: 200},
			{Code: 200},
		}...)

		// Set in past to re-create transport
		spec.HTTPTransportCreated = time.Now().Add(-time.Minute)

		// Should be called in new connection
		// We already made 2 requests above, so 3th in same not allowed
		_, _ = ts.Run(t, test.TestCase{Code: 200})
	})
}

// TestRateLimitForAPIAndRateLimitAndQuotaCheck ensures that the Rate Limit for the key is applied before the rate limit
// for the API. Meaning that a single token cannot reduce service availability for other tokens by simply going over the
// API's global rate limit.
func TestRateLimitForAPIAndRateLimitAndQuotaCheck(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	globalCfg := ts.Gw.GetConfig()
	globalCfg.EnableNonTransactionalRateLimiter = false
	globalCfg.EnableSentinelRateLimiter = true
	ts.Gw.SetConfig(globalCfg)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
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

	sess1token := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})
	defer ts.Gw.GlobalSessionManager.RemoveSession("default", sess1token, false)

	sess2token := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 1
		s.Per = 60
	})
	defer ts.Gw.GlobalSessionManager.RemoveSession("default", sess2token, false)

	_, _ = ts.Run(t, []test.TestCase{
		{Headers: map[string]string{"Authorization": sess1token}, Code: http.StatusOK, Path: "/", Delay: 100 * time.Millisecond},
		{Headers: map[string]string{"Authorization": sess1token}, Code: http.StatusTooManyRequests, Path: "/"},
		{Headers: map[string]string{"Authorization": sess2token}, Code: http.StatusOK, Path: "/", Delay: 100 * time.Millisecond},
		{Headers: map[string]string{"Authorization": sess2token}, Code: http.StatusTooManyRequests, Path: "/"},
	}...)
}

func TestTracing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.prepareStorage()
	spec := BuildAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = false
	})[0]

	keyID := CreateSession(ts.Gw)
	authHeaders := map[string][]string{"Authorization": {keyID}}

	_, _ = ts.Run(t, []test.TestCase{
		{Method: "GET", Path: "/tyk/debug", AdminAuth: true, Code: 405},
		{Method: "POST", Path: "/tyk/debug", AdminAuth: true, Code: 400, BodyMatch: "Request malformed"},
		{Method: "POST", Path: "/tyk/debug", Data: `{}`, AdminAuth: true, Code: 400, BodyMatch: "Spec field is missing"},
		{Method: "POST", Path: "/tyk/debug", Data: `{"Spec": {}}`, AdminAuth: true, Code: 400, BodyMatch: "Request field is missing"},
		{Method: "POST", Path: "/tyk/debug", Data: `{"Spec": {}, "Request": {}}`, AdminAuth: true, Code: 400, BodyMatch: "Spec not valid, skipped!"},
		{Method: "POST", Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition, Request: &traceHttpRequest{Method: "GET", Path: "/"}}, AdminAuth: true, Code: 200, BodyMatch: `401 Unauthorized`},
		{Method: "POST", Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition, Request: &traceHttpRequest{Path: "/", Headers: authHeaders}}, AdminAuth: true, Code: 200, BodyMatch: `200 OK`},
	}...)

	t.Run("Custom auth header", func(t *testing.T) {
		spec.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				AuthHeaderName: "Custom-Auth-Header",
			},
		}

		customAuthHeaders := map[string][]string{"custom-auth-header": {keyID}}

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPost, Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition,
				Request: &traceHttpRequest{Path: "/", Headers: authHeaders}}, AdminAuth: true, Code: 200, BodyMatch: `401 Unauthorized`},
			{Method: http.MethodPost, Path: "/tyk/debug", Data: traceRequest{Spec: spec.APIDefinition,
				Request: &traceHttpRequest{Path: "/", Headers: customAuthHeaders}}, AdminAuth: true, Code: 200, BodyMatch: `200 OK`},
		}...)
	})
}

func TestBrokenClients(t *testing.T) {

	conf := func(gwConf *config.Config) {
		gwConf.ProxyDefaultTimeout = 1
	}
	ts := StartTest(conf)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.EnforcedTimeoutEnabled = true
	})

	buf := make([]byte, 1024)

	t.Run("Valid client", func(t *testing.T) {
		conn, _ := net.DialTimeout("tcp", ts.mainProxy().listener.Addr().String(), 0)
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		conn.Read(buf)

		if string(buf[:12]) != "HTTP/1.1 200" {
			t.Error("Invalid server response:", string(buf))
		}
	})

	t.Run("Invalid client: close without read", func(t *testing.T) {
		time.Sleep(recordsBufferFlushInterval + 50*time.Millisecond)
		ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		conn, _ := net.DialTimeout("tcp", ts.mainProxy().listener.Addr().String(), 0)
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		conn.Close()
		//conn.Read(buf)

		time.Sleep(recordsBufferFlushInterval + 50*time.Millisecond)
		results := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

		var record analytics.AnalyticsRecord
		msgpack.Unmarshal([]byte(results[0].(string)), &record)
		if record.ResponseCode != 499 {
			t.Fatal("Analytics record do not match:", record)
		}
	})
}

func TestCache_singleErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))

	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
		spec.Proxy.TargetURL = srv.URL
		spec.CacheOptions.CacheTimeout = 1
		spec.CacheOptions.EnableCache = true
		spec.CacheOptions.CacheAllSafeRequests = true
	})

	_, _ = ts.Run(t,
		test.TestCase{Method: http.MethodGet, Path: "/", Code: http.StatusOK},
	)

	srv.Close()

	_, _ = ts.Run(t,
		test.TestCase{Method: http.MethodGet, Path: "/", Code: http.StatusOK},
	)

	time.Sleep(time.Second)

	wantBody := `{
    "error": "There was a problem proxying the request"
}`
	_, _ = ts.Run(t,
		test.TestCase{Method: http.MethodGet, Path: "/", Code: http.StatusInternalServerError, BodyMatch: wantBody},
	)
}

func TestOverrideErrors(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	defer defaultTykErrors()

	assert := func(expectedError string, expectedCode int, actualError error, actualCode int) {
		if !(expectedError == actualError.Error() && expectedCode == actualCode) {
			t.Fatal("Override failed")
		}
	}

	const message1 = "Message1"
	const code1 = 901
	const message2 = "Message2"
	const code2 = 902
	const message3 = "Message3"
	const code3 = 903
	const message4 = "Message4"
	const code4 = 904
	const message5 = "Message5"
	const code5 = 905
	const message6 = "Message6"
	const code6 = 906

	testConf := ts.Gw.GetConfig()

	testConf.OverrideMessages = map[string]config.TykError{
		ErrOAuthAuthorizationFieldMissing: {
			Message: message1,
			Code:    code1,
		},
		ErrOAuthAuthorizationFieldMalformed: {
			Message: message2,
			Code:    code2,
		},
		ErrOAuthKeyNotFound: {
			Message: message3,
			Code:    code3,
		},
		ErrOAuthClientDeleted: {
			Message: message4,
			Code:    code4,
		},
		ErrAuthAuthorizationFieldMissing: {
			Message: message5,
			Code:    code5,
		},
		ErrAuthKeyNotFound: {
			Message: message6,
			Code:    code6,
		},
	}
	ts.Gw.SetConfig(testConf)

	overrideTykErrors(ts.Gw)

	e, i := errorAndStatusCode(ErrOAuthAuthorizationFieldMissing)
	assert(message1, code1, e, i)

	e, i = errorAndStatusCode(ErrOAuthAuthorizationFieldMalformed)
	assert(message2, code2, e, i)

	e, i = errorAndStatusCode(ErrOAuthKeyNotFound)
	assert(message3, code3, e, i)

	e, i = errorAndStatusCode(ErrOAuthClientDeleted)
	assert(message4, code4, e, i)

	e, i = errorAndStatusCode(ErrAuthAuthorizationFieldMissing)
	assert(message5, code5, e, i)

	e, i = errorAndStatusCode(ErrAuthKeyNotFound)
	assert(message6, code6, e, i)

	t.Run("Partial override", func(t *testing.T) {
		testConf.OverrideMessages = map[string]config.TykError{
			ErrOAuthAuthorizationFieldMissing: {
				Code: code4,
			},
			ErrOAuthAuthorizationFieldMalformed: {
				Message: message4,
			},
		}

		ts.Gw.SetConfig(testConf)

		overrideTykErrors(ts.Gw)

		e, i := errorAndStatusCode(ErrOAuthAuthorizationFieldMissing)
		assert(message1, code4, e, i)

		e, i = errorAndStatusCode(ErrOAuthAuthorizationFieldMalformed)
		assert(message4, code2, e, i)
	})

}
