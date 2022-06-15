//go:build coprocess && !python && !grpc
// +build coprocess,!python,!grpc

package coprocess_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/justinas/alice"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/gateway"
	logger "github.com/TykTechnologies/tyk/log"
)

const baseMiddlewarePath = "middleware/python"

var (
	testDispatcher, _ = gateway.NewCoProcessDispatcher()
	log               = logger.Get()

	coprocessLog = log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	})
)

func TestMain(m *testing.M) {
	os.Exit(gateway.InitTestMain(context.Background(), m))
}

/* Dispatcher functions */

func TestCoProcessDispatch(t *testing.T) {
	object := &coprocess.Object{
		HookType: coprocess.HookType_Pre,
		HookName: "test",
	}

	messagePtr := testDispatcher.ToCoProcessMessage(object)
	newMessagePtr := testDispatcher.ToCoProcessMessage(&coprocess.Object{})
	testDispatcher.Dispatch(messagePtr, newMessagePtr)
}

func TestCoProcessDispatchEvent(t *testing.T) {
	ts := gateway.StartTest()
	defer ts.Close()

	spec := ts.Gw.LoadSampleAPI().LoadSampleAPI(basicCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)

	proxy := gateway.TykNewSingleHostReverseProxy(remote, spec)
	baseMid := gateway.BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw}

	meta := gateway.EventKeyFailureMeta{
		EventMetaDefault: gateway.EventMetaDefault{Message: "Auth Failure"},
		Path:             "/",
		Origin:           "127.0.0.1",
		Key:              "abc",
	}

	baseMid.FireEvent(gateway.EventAuthFailure, meta)

	wrapper := gateway.CoProcessEventWrapper{}
	if err := json.Unmarshal(<-gateway.CoProcessDispatchEvent, &wrapper); err != nil {
		t.Fatal(err)
	}

	if wrapper.Event.Type != gateway.EventAuthFailure {
		t.Fatal("Wrong event type")
	}

	got := wrapper.Event.Meta.(map[string]interface{})
	if got["Message"] != meta.Message || got["Path"] != meta.Path || got["Origin"] != meta.Origin || got["Key"] != meta.Key {
		t.Fatalf("Wrong event metadata\ngot: %#v\nwant: %#v", got, meta)
	}
}

func TestCoProcessReload(t *testing.T) {
	// Use this as the GlobalDispatcher:
	gateway.GlobalDispatcher = testDispatcher
	gateway.DoCoprocessReload()
	if !testDispatcher.Reloaded {
		t.Fatal("coprocess reload wasn't run")
	}
}

/* Serialization, CP Objects */
func TestCoProcessSerialization(t *testing.T) {
	object := &coprocess.Object{
		HookType: coprocess.HookType_Pre,
		HookName: "test_hook",
	}

	data, err := proto.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}

	messagePtr := testDispatcher.ToCoProcessMessage(object)
	length := testDispatcher.TestMessageLength(messagePtr)

	if len(data) != length {
		t.Fatal("The length of the serialized object doesn't match")
	}
}

/* Gateway API */

func TestCoProcessGetSetData(t *testing.T) {
	key := "testkey"
	value := "testvalue"
	ttl := 1000

	gateway.TestTykStoreData(key, value, ttl)

	retrievedValue := gateway.TestTykGetData("testkey")

	if retrievedValue != value {
		t.Fatal("Couldn't retrieve key value using CP API")
	}
}

func TestCoProcessTykTriggerEvent(t *testing.T) {
	gateway.TestTykTriggerEvent("testevent", "testpayload")
}

/* Middleware */

func buildCoProcessChain(spec *gateway.APISpec, hookName string, hookType coprocess.HookType, driver apidef.MiddlewareDriver) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := gateway.TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := gateway.ProxyHandler(proxy, spec)

	ts := gateway.StartTest(nil)
	defer ts.Close()

	baseMid := gateway.BaseMiddleware{Spec: spec, Proxy: proxy, Gw: ts.Gw} // TODO
	mw := gateway.CreateCoProcessMiddleware(hookName, hookType, driver, baseMid)
	return alice.New(mw).Then(proxyHandler)
}

func TestCoProcessMiddleware(t *testing.T) {
	spec := gateway.LoadSampleAPI(basicCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))

	session := gateway.CreateStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := gateway.TestReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)
}

func TestCoProcessObjectPostProcess(t *testing.T) {
	spec := gateway.LoadSampleAPI(basicCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test_object_postprocess", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))

	session := gateway.CreateStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := gateway.TestReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")
	req.Header.Set("Deletethisheader", "value")

	chain.ServeHTTP(recorder, req)

	resp := gateway.TestHttpResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Headers["Test"] != "value" {
		t.Fatal("ObjectPostProcess couldn't add a header.")
	}
	if resp.Headers["Deletethisheader"] != "" {
		t.Fatal("ObjectPostProcess couldn't delete a header.")
	}

	recorder = httptest.NewRecorder()

	uri := "/get?a=a_value&b=123&remove=3"
	req = gateway.TestReq(t, "GET", uri, nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)

	resp = gateway.TestHttpResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Form["a"] != "a_value" || resp.Form["b"] != "123" {
		t.Fatal("The original parameters don't match.")
	}
	if resp.Form["remove"] != "" {
		t.Fatal("ObjectPostProcess couldn't remove a parameter.")
	}
	if resp.Form["customparam"] != "customvalue" {
		t.Fatal("ObjectPostProcess couldn't set custom parameters.")
	}
}

/* CP authentication */

func TestCoProcessAuth(t *testing.T) {
	t.Log("CP AUTH")
	spec := gateway.LoadSampleAPI(protectedCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test_bad_auth", coprocess.HookType_CustomKeyCheck, apidef.MiddlewareDriver("python"))

	session := gateway.CreateStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := gateway.TestReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Fatal("Authentication should fail! But it's returning:", recorder.Code)
	}
	<-gateway.CoProcessDispatchEvent
}

func TestCoProcessReturnOverrides(t *testing.T) {
	spec := gateway.LoadSampleAPI(t, basicCoProcessDef)
	chain := buildCoProcessChain(spec, "hook_test_return_overrides", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))
	session := gateway.CreateStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := gateway.TestReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")
	chain.ServeHTTP(recorder, req)
	if recorder.Code != 200 || recorder.Body.String() != "body" {
		t.Fatal("ReturnOverrides HTTP response is invalid")
	}
	headerValue := recorder.Header().Get("header")
	if headerValue != "value" {
		t.Fatal("ReturnOverrides HTTP header is not present")
	}
}

func TestCoProcessReturnOverridesErrorMessage(t *testing.T) {
	spec := gateway.LoadSampleAPI(basicCoProcessDef)
	chain := buildCoProcessChain(spec, "hook_test_return_overrides_error", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))
	session := gateway.CreateStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := gateway.TestReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")
	chain.ServeHTTP(recorder, req)
	if recorder.Code != 401 || recorder.Body.String() != "{\n    \"error\": \"custom error message\"\n}" {
		t.Fatal("ReturnOverrides HTTP response is invalid", recorder.Code, recorder.Body)
	}
}

const basicCoProcessDef = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"event_handlers": {
		"events": {"AuthFailure": [{
			"handler_name":"cp_dynamic_handler",
			"handler_meta": {
				"name": "my_handler"
			}
		}]}
	},
	"custom_middleware": {
		"pre": [{"name": "MyPreMiddleware"}],
		"driver": "python"
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + gateway.TestHttpGet + `"
	}
}`

const protectedCoProcessDef = `{
	"api_id": "1",
	"auth": {"auth_header_name": "authorization"},
	"enable_coprocess_auth": true,
	"version_data": {
		"not_versioned": true,
		"versions": {
			"v1": {"name": "v1"}
		}
	},
	"event_handlers": {
		"events": {"AuthFailure": [{
			"handler_name":"cp_dynamic_handler",
			"handler_meta": {
				"name": "my_handler"
			}
		}]}
	},
	"custom_middleware": {
		"auth_check": {
			"name": "TestAuthCheck"
		},
		"driver": "python"
	},
	"proxy": {
		"listen_path": "/v1",
		"target_url": "` + gateway.TestHttpGet + `"
	}
}`
