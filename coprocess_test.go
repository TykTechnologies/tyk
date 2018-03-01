// +build coprocess
// +build !python
// +build !grpc

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

const baseMiddlewarePath = "middleware/python"

var (
	CoProcessName     = apidef.MiddlewareDriver("test")
	MessageType       = coprocess.ProtobufMessage
	testDispatcher, _ = NewCoProcessDispatcher()
)

/* Dispatcher functions */

func TestCoProcessDispatch(t *testing.T) {
	object := &coprocess.Object{
		HookType: coprocess.HookType_Pre,
		HookName: "test",
	}

	messagePtr := testDispatcher.ToCoProcessMessage(object)
	newMessagePtr := testDispatcher.Dispatch(messagePtr)

	newObject := testDispatcher.ToCoProcessObject(newMessagePtr)
	t.Log(newObject)
}

func TestCoProcessDispatchEvent(t *testing.T) {
	spec := createSpecTest(t, basicCoProcessDef)
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	baseMid := BaseMiddleware{spec, proxy}

	meta := EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{Message: "Auth Failure"},
		Path:             "/",
		Origin:           "127.0.0.1",
		Key:              "abc",
	}

	baseMid.FireEvent(EventAuthFailure, meta)

	wrapper := CoProcessEventWrapper{}
	if err := json.Unmarshal(<-CoProcessDispatchEvent, &wrapper); err != nil {
		t.Fatal(err)
	}

	if wrapper.Event.Type != EventAuthFailure {
		t.Fatal("Wrong event type")
	}

	got := wrapper.Event.Meta.(map[string]interface{})
	if got["Message"] != meta.Message || got["Path"] != meta.Path || got["Origin"] != meta.Origin || got["Key"] != meta.Key {
		t.Fatalf("Wrong event metadata\ngot: %#v\nwant: %#v", got, meta)
	}
}

func TestCoProcessReload(t *testing.T) {
	testDispatcher.reloaded = false
	var wg sync.WaitGroup
	wg.Add(1)
	reloadURLStructure(wg.Done)
	reloadTick <- time.Time{}
	wg.Wait()
	if !testDispatcher.reloaded {
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

	TestTykStoreData(key, value, ttl)

	retrievedValue := TestTykGetData("testkey")

	if retrievedValue != value {
		t.Fatal("Couldn't retrieve key value using CP API")
	}
}

func TestCoProcessTykTriggerEvent(t *testing.T) {
	TestTykTriggerEvent("testevent", "testpayload")
}

/* Middleware */

func buildCoProcessChain(spec *APISpec, hookName string, hookType coprocess.HookType, driver apidef.MiddlewareDriver) http.Handler {
	remote, _ := url.Parse(spec.Proxy.TargetURL)
	proxy := TykNewSingleHostReverseProxy(remote, spec)
	proxyHandler := ProxyHandler(proxy, spec)
	baseMid := BaseMiddleware{spec, proxy}
	mw := CreateCoProcessMiddleware(hookName, hookType, driver, baseMid)
	return alice.New(mw).Then(proxyHandler)
}

func TestCoProcessMiddleware(t *testing.T) {
	spec := createSpecTest(t, basicCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))

	session := createStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)
}

func TestCoProcessObjectPostProcess(t *testing.T) {
	spec := createSpecTest(t, basicCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test_object_postprocess", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))

	session := createStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")
	req.Header.Set("Deletethisheader", "value")

	chain.ServeHTTP(recorder, req)

	resp := testHttpResponse{}
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
	req = testReq(t, "GET", uri, nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)

	resp = testHttpResponse{}
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
	spec := createSpecTest(t, protectedCoProcessDef)

	chain := buildCoProcessChain(spec, "hook_test_bad_auth", coprocess.HookType_CustomKeyCheck, apidef.MiddlewareDriver("python"))

	session := createStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/headers", nil)
	req.Header.Set("authorization", "abc")

	chain.ServeHTTP(recorder, req)

	if recorder.Code != 403 {
		t.Fatal("Authentication should fail! But it's returning:", recorder.Code)
	}
	<-CoProcessDispatchEvent
}

func TestCoProcessReturnOverrides(t *testing.T) {
	spec := createSpecTest(t, basicCoProcessDef)
	chain := buildCoProcessChain(spec, "hook_test_return_overrides", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))
	session := createStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/headers", nil)
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
	spec := createSpecTest(t, basicCoProcessDef)
	chain := buildCoProcessChain(spec, "hook_test_return_overrides_error", coprocess.HookType_Pre, apidef.MiddlewareDriver("python"))
	session := createStandardSession()
	spec.SessionManager.UpdateSession("abc", session, 60, false)

	recorder := httptest.NewRecorder()

	req := testReq(t, "GET", "/headers", nil)
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
		"target_url": "` + testHttpGet + `"
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
		"target_url": "` + testHttpGet + `"
	}
}`
