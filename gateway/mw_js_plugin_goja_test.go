package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// drivers runs subtests against both otto and goja to verify identical behaviour.
var drivers = []apidef.MiddlewareDriver{apidef.OttoDriver, apidef.JavaScriptDriver}

// initJSVM initialises the correct JSVM type on the spec for the given driver
// and loads the JS source into it.
func initJSVM(t *testing.T, spec *APISpec, gw *Gateway, driver apidef.MiddlewareDriver, js string) {
	t.Helper()
	spec.CustomMiddleware.Driver = driver

	if driver == apidef.JavaScriptDriver {
		spec.GojaJSVM.Init(spec, log.NewEntry(), gw)
		if err := spec.GojaJSVM.LoadScript(js); err != nil {
			t.Fatalf("failed to load JS into GojaJSVM: %v", err)
		}
	} else {
		spec.JSVM.Init(spec, log.NewEntry(), gw)
		if _, err := spec.JSVM.VM.Run(js); err != nil {
			t.Fatalf("failed to load JS into otto JSVM: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// 1. Pre hook — header injection
// ---------------------------------------------------------------------------

func TestGoja_PreHookHeaderInjection(t *testing.T) {
	const js = `
var headerHook = new TykJS.TykMiddleware.NewMiddleware({});

headerHook.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Engine-Test"] = "true";
	return headerHook.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "header_test_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"hook.js": js,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Pre: []apidef.MiddlewareDefinition{{
						Name: "headerHook",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/hook.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path: "/test", Code: http.StatusOK, BodyMatch: `"X-Engine-Test":"true"`,
			})
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Body manipulation — b64 round-trip through DoProcessRequest
// ---------------------------------------------------------------------------

func TestGoja_BodyManipulation(t *testing.T) {
	const js = `
var bodyMid = new TykJS.TykMiddleware.NewMiddleware({});

bodyMid.NewProcessRequest(function(request, session) {
	request.Body += " appended";
	return bodyMid.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			dynMid := &DynamicMiddleware{
				BaseMiddleware:      &BaseMiddleware{Spec: spec, Gw: ts.Gw},
				MiddlewareClassName: "bodyMid",
				Pre:                 true,
			}

			initJSVM(t, spec, ts.Gw, driver, js)

			body := "hello world"
			req := httptest.NewRequest("GET", "/foo", strings.NewReader(body))
			processErr, _ := dynMid.ProcessRequest(nil, req, nil)
			assert.NoError(t, processErr)

			got, readErr := io.ReadAll(req.Body)
			assert.NoError(t, readErr)
			assert.Equal(t, "hello world appended", string(got))
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Session metadata update
// ---------------------------------------------------------------------------

func TestGoja_SessionMetadataUpdate(t *testing.T) {
	const js = `
var metaMid = new TykJS.TykMiddleware.NewMiddleware({});

metaMid.NewProcessRequest(function(request, session) {
	return metaMid.ReturnData(request, {same: "same", updated: "new"});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			dynMid := &DynamicMiddleware{
				BaseMiddleware:      &BaseMiddleware{Spec: spec, Gw: ts.Gw},
				MiddlewareClassName: "metaMid",
				Pre:                 false,
				UseSession:          true,
			}

			initJSVM(t, spec, ts.Gw, driver, js)

			req := httptest.NewRequest("GET", "/foo", nil)
			s := &user.SessionState{MetaData: map[string]interface{}{
				"same":    "same",
				"updated": "old",
				"removed": "dummy",
			}}
			ctxSetSession(req, s, true, ts.Gw.GetConfig().HashKeys)

			processErr, _ := dynMid.ProcessRequest(nil, req, nil)
			assert.NoError(t, processErr)

			updated := ctx.GetSession(req)
			assert.Equal(t, "same", updated.MetaData["same"])
			assert.Equal(t, "new", updated.MetaData["updated"])
			assert.Nil(t, updated.MetaData["removed"])
		})
	}
}

// ---------------------------------------------------------------------------
// 4. Timeout handling
// ---------------------------------------------------------------------------

func TestGoja_Timeout(t *testing.T) {
	const js = `
var timeoutMid = new TykJS.TykMiddleware.NewMiddleware({});

timeoutMid.NewProcessRequest(function(request, session) {
	while (true) {}
	return timeoutMid.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			dynMid := &DynamicMiddleware{
				BaseMiddleware:      &BaseMiddleware{Spec: spec, Gw: ts.Gw},
				MiddlewareClassName: "timeoutMid",
				Pre:                 true,
			}

			initJSVM(t, spec, ts.Gw, driver, js)

			// Set a very short timeout
			if driver == apidef.JavaScriptDriver {
				spec.GojaJSVM.Timeout = 50 * time.Millisecond
			} else {
				spec.JSVM.Timeout = 50 * time.Millisecond
			}

			req := httptest.NewRequest("GET", "/foo", strings.NewReader("body"))

			done := make(chan bool, 1)
			go func() {
				err, code := dynMid.ProcessRequest(nil, req, nil)
				assert.NotNil(t, err)
				assert.Equal(t, http.StatusInternalServerError, code)
				done <- true
			}()

			select {
			case <-done:
				// passed
			case <-time.After(3 * time.Second):
				t.Fatal("JS middleware wasn't killed after timeout")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. Config data access from JS
// ---------------------------------------------------------------------------

func TestGoja_ConfigData(t *testing.T) {
	const js = `
var configMid = new TykJS.TykMiddleware.NewMiddleware({});

configMid.NewProcessRequest(function(request, session, spec) {
	request.SetHeaders["X-Config-Foo"] = spec.config_data.foo;
	return configMid.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
			spec.ConfigData = map[string]interface{}{"foo": "bar"}

			dynMid := &DynamicMiddleware{
				BaseMiddleware:      &BaseMiddleware{Spec: spec, Proxy: nil, Gw: ts.Gw},
				MiddlewareClassName: "configMid",
				Pre:                 true,
			}

			initJSVM(t, spec, ts.Gw, driver, js)

			r := TestReq(t, "GET", "/test", nil)
			processErr, _ := dynMid.ProcessRequest(nil, r, nil)
			assert.NoError(t, processErr)
			assert.Equal(t, "bar", r.Header.Get("X-Config-Foo"))
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Auth plugin — full integration via BuildAndLoadAPI
// ---------------------------------------------------------------------------

func TestGoja_Auth(t *testing.T) {
	const authJS = `
var jsAuth = new TykJS.TykMiddleware.NewMiddleware({});

jsAuth.NewProcessRequest(function(request, session) {
	var token = request.Headers["Authorization"];
	if (token == undefined) {
		request.ReturnOverrides.ResponseCode = 401;
		request.ReturnOverrides.ResponseError = "Header missing";
		return jsAuth.ReturnData(request, {});
	}
	if (token != "valid-token") {
		request.ReturnOverrides.ResponseCode = 401;
		request.ReturnOverrides.ResponseError = "Not authorized";
		return jsAuth.ReturnData(request, {});
	}
	var thisSession = {
		"allowance": 100, "rate": 100, "per": 1,
		"quota_max": -1, "quota_renews": 1906121006,
		"expires": 1906121006, "access_rights": {}
	};
	return jsAuth.ReturnAuthData(request, thisSession);
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(func(c *config.Config) {
				c.HashKeys = false
			})
			defer ts.Close()

			apiID := "auth_test_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"auth.js": authJS,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/auth-test"
				spec.UseKeylessAccess = false
				spec.CustomPluginAuthEnabled = true
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					AuthCheck: apidef.MiddlewareDefinition{
						Name: "jsAuth",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/auth.js",
					},
				}
			})

			ts.Run(t, []test.TestCase{
				// No token → 401
				{Path: "/auth-test", Code: http.StatusUnauthorized,
					BodyMatchFunc: func(b []byte) bool {
						return strings.Contains(string(b), "Header missing")
					}},
				// Bad token → 401
				{Path: "/auth-test", Code: http.StatusUnauthorized,
					Headers: map[string]string{"Authorization": "wrong"},
					BodyMatchFunc: func(b []byte) bool {
						return strings.Contains(string(b), "Not authorized")
					}},
				// Good token → 200
				{Path: "/auth-test", Code: http.StatusOK,
					Headers: map[string]string{"Authorization": "valid-token"}},
			}...)
		})
	}
}

// ---------------------------------------------------------------------------
// 7. Pre + Post stages via file-based middleware
// ---------------------------------------------------------------------------

func TestGoja_PrePostStages(t *testing.T) {
	const preJS = `var pre = new TykJS.TykMiddleware.NewMiddleware({});
pre.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Pre"] = "pre-ok";
	request.AddParams["pre"] = "1";
	return pre.ReturnData(request, {"pre": "ok"});
});`

	const postJS = `var post = new TykJS.TykMiddleware.NewMiddleware({});
post.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Post"] = "post-ok";
	request.AddParams["post"] = "1";
	return post.ReturnData(request, {"post": "ok"});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			ts.RegisterJSFileMiddleware("stages_"+string(driver), map[string]string{
				"pre/pre.js":   preJS,
				"post/post.js": postJS,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = "stages_" + string(driver)
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Pre: []apidef.MiddlewareDefinition{{
						Name: "pre",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/stages_" + string(driver) + "/pre/pre.js",
					}},
					Post: []apidef.MiddlewareDefinition{{
						Name: "post",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/stages_" + string(driver) + "/post/post.js",
					}},
				}
			})

			ts.Run(t, []test.TestCase{
				{Path: "/test", Code: http.StatusOK, BodyMatch: `"X-Pre":"pre-ok"`},
				{Path: "/test", Code: http.StatusOK, BodyMatch: `"X-Post":"post-ok"`},
			}...)
		})
	}
}

// ---------------------------------------------------------------------------
// 8. Base64 round-trip via GojaJSVM.Run directly
// ---------------------------------------------------------------------------

func TestGoja_Base64(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	gojaVM := GojaJSVM{}
	gojaVM.Init(nil, log.NewEntry(), ts.Gw)

	tests := []struct {
		name string
		expr string
		want string
	}{
		{"b64enc", `b64enc("teststring")`, "dGVzdHN0cmluZw=="},
		{"b64dec", `b64dec("dGVzdHN0cmluZw==")`, "teststring"},
		{"rawb64dec JWT", `b64dec("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")`,
			`{"sub":"1234567890","name":"John Doe","iat":1516239022}`},
		{"rawb64enc", `rawb64enc("{\"sub\":\"1234567890\"}")`, "eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gojaVM.Run(tc.expr)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// 9. Post-auth (post_key_auth) hook — header injection after authentication
// ---------------------------------------------------------------------------

func TestGoja_PostKeyAuthHook(t *testing.T) {
	const postAuthJS = `
var postAuth = new TykJS.TykMiddleware.NewMiddleware({});

postAuth.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Post-Auth"] = "true";
	return postAuth.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "post_key_auth_test_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"post_auth.js": postAuthJS,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.OrgID = "default"
				spec.Proxy.ListenPath = "/post-auth-test"
				spec.UseKeylessAccess = false
				spec.UseStandardAuth = true
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					PostKeyAuth: []apidef.MiddlewareDefinition{{
						Name: "postAuth",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/post_auth.js",
					}},
				}
			})

			_, key := ts.CreateSession(func(s *user.SessionState) {
				s.AccessRights = map[string]user.AccessDefinition{
					apiID: {
						APIID:    apiID,
						Versions: []string{"Default"},
					},
				}
			})

			ts.Run(t, []test.TestCase{
				// Request without auth key should be rejected.
				{Path: "/post-auth-test", Code: http.StatusUnauthorized},
				// Request with valid auth key should succeed and include
				// the header injected by the post_key_auth JS middleware.
				{Path: "/post-auth-test", Code: http.StatusOK,
					Headers:   map[string]string{"Authorization": key},
					BodyMatch: `"X-Post-Auth":"true"`},
			}...)
		})
	}
}

// ---------------------------------------------------------------------------
// 10. Bundle-based middleware (verifies bundles work with goja driver)
// ---------------------------------------------------------------------------

func TestGoja_Bundle(t *testing.T) {
	const preJS = `
var bundlePre = new TykJS.TykMiddleware.NewMiddleware({});
bundlePre.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Bundle-Engine"] = "yes";
	return bundlePre.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			bundle := ts.RegisterBundle("bundle_"+string(driver), map[string]string{
				"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "` + string(driver) + `",
		        "pre": [{
		            "name": "bundlePre",
		            "path": "pre.js"
		        }]
		    },
		    "checksum": "d41d8cd98f00b204e9800998ecf8427e"
		}`,
				"pre.js": preJS,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddlewareBundle = bundle
			})

			ts.Run(t, test.TestCase{
				Path: "/test", Code: http.StatusOK, BodyMatch: `"X-Bundle-Engine":"yes"`,
			})
		})
	}
}

// ---------------------------------------------------------------------------
// 11. GojaJSVM edge cases — DeInit, VM(), Run when not initialized
// ---------------------------------------------------------------------------

func TestGoja_DeInit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)
	assert.True(t, vm.Initialized())
	assert.NotNil(t, vm.VM())

	vm.DeInit()
	assert.False(t, vm.Initialized())
	assert.Nil(t, vm.VM())
}

func TestGoja_RunNotInitialized(t *testing.T) {
	vm := GojaJSVM{}
	assert.False(t, vm.Ready())
	assert.Nil(t, vm.VM())

	_, err := vm.Run(`"hello"`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JSVM isn't enabled")
}

func TestGoja_LoadScriptCompileError(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)

	err := vm.LoadScript("function {{{ invalid syntax")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// 11b. GojaJSVM Init — TykJSPath and custom timeout branches
// ---------------------------------------------------------------------------

func TestGoja_Init_TykJSPath_Valid(t *testing.T) {
	dir := t.TempDir()
	jsFile := dir + "/user.js"
	require.NoError(t, os.WriteFile(jsFile, []byte("function myHelper() { return 42; }"), 0644))

	ts := StartTest(func(c *config.Config) {
		c.TykJSPath = jsFile
	})
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)
	assert.True(t, vm.Initialized())

	// coreJS + userJS + TykJsResponse = 3 programs
	assert.Equal(t, 3, len(vm.programs))

	// The user-defined function should be available at runtime.
	result, err := vm.Run("myHelper()")
	assert.NoError(t, err)
	assert.Equal(t, "42", result)
}

func TestGoja_Init_TykJSPath_CompileError(t *testing.T) {
	dir := t.TempDir()
	jsFile := dir + "/bad.js"
	require.NoError(t, os.WriteFile(jsFile, []byte("function {{{ bad syntax"), 0644))

	ts := StartTest(func(c *config.Config) {
		c.TykJSPath = jsFile
	})
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)
	assert.True(t, vm.Initialized())

	// Bad JS skipped — only coreJS + TykJsResponse remain.
	assert.Equal(t, 2, len(vm.programs))
}

func TestGoja_Init_CustomTimeout(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.JSVMTimeout = 15
	})
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)
	assert.Equal(t, 15*time.Second, vm.Timeout)
}

// ---------------------------------------------------------------------------
// 11c. registerAPI closures — error and success paths via the JS VM
// ---------------------------------------------------------------------------

// TestGoja_RegisterAPI_ErrorPaths exercises the if-err branches inside every
// set() closure in registerAPI, ensuring goja.Undefined() is returned instead
// of panicking.  These lines are only reachable through the JS VM.
func TestGoja_RegisterAPI_ErrorPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// nil spec is safe here — all tested code paths fail before accessing Spec.
	gojaVM := GojaJSVM{}
	gojaVM.Init(nil, log.NewEntry(), ts.Gw)

	tests := []struct {
		name string
		js   string
		want string // expected typeof result
	}{
		// b64dec error path: invalid base64 → undefined
		{"b64dec_error", "typeof b64dec('!!invalid!!')", "undefined"},
		// rawb64dec error path: invalid raw-base64 → undefined
		{"rawb64dec_error", "typeof rawb64dec('!!invalid!!')", "undefined"},
		// rawb64dec success path: valid raw-base64 → string
		{"rawb64dec_success", `rawb64dec("dGVzdA")`, "test"},
		// log and rawlog success paths (must not throw)
		{"log_call", `log("msg"); "ok"`, "ok"},
		{"rawlog_call", `rawlog("msg"); "ok"`, "ok"},
		// TykMakeHttpRequest: bad JSON → undefined
		{"TykMakeHttpRequest_badJSON", "typeof TykMakeHttpRequest('{invalid}')", "undefined"},
		// TykMakeHttpRequest: undefined sentinel → undefined
		{"TykMakeHttpRequest_undefined", "typeof TykMakeHttpRequest('undefined')", "undefined"},
		// TykBatchRequest: bad JSON → undefined
		{"TykBatchRequest_badJSON", "typeof TykBatchRequest('{invalid}')", "undefined"},
		// TykSetKeyData: bad JSON session → logs error, returns undefined
		{"TykSetKeyData_badJSON", "typeof TykSetKeyData('key','notjson','0')", "undefined"},
		// TykGetKeyData: non-existent key → returns a JSON string
		{"TykGetKeyData_notFound", `typeof TykGetKeyData("no-such-key","")`, "string"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := gojaVM.Run(tc.js)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, result)
		})
	}
}

// TestGoja_TykMakeHttpRequest_Via_JS covers the success path of
// TykMakeHttpRequest (the vm.ToValue branch) via a real HTTP server.
func TestGoja_TykMakeHttpRequest_Via_JS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("hello from server")); err != nil {
			t.Errorf("w.Write: %v", err)
		}
	}))
	defer server.Close()

	ts := StartTest(nil)
	defer ts.Close()

	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
	gojaVM := GojaJSVM{}
	gojaVM.Init(spec, log.NewEntry(), ts.Gw)

	js := fmt.Sprintf(`TykMakeHttpRequest('{"Method":"GET","Domain":"%s","Resource":"/"}')`, server.URL)
	result, err := gojaVM.Run(js)
	assert.NoError(t, err)
	assert.Contains(t, result, "hello from server")
}

// ---------------------------------------------------------------------------
// 12. LoadJSPaths — unsupported extension, missing file, compile error
// ---------------------------------------------------------------------------

func TestGoja_LoadJSPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)

	initialCount := len(vm.programs)

	// Unsupported extension — should skip, not crash.
	vm.LoadJSPaths([]string{"plugin.py"}, "")
	assert.Equal(t, initialCount, len(vm.programs), "should not load non-.js file")

	// Missing file — should skip, not crash.
	vm.LoadJSPaths([]string{"nonexistent.js"}, "")
	assert.Equal(t, initialCount, len(vm.programs), "should not load missing file")

	// Valid file with bad JS — should skip, not crash.
	dir := t.TempDir()
	badFile := dir + "/bad.js"
	if err := os.WriteFile(badFile, []byte("function {{{ invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	vm.LoadJSPaths([]string{"bad.js"}, dir)
	assert.Equal(t, initialCount, len(vm.programs), "should not load file with syntax error")

	// Valid JS file — should load.
	goodFile := dir + "/good.js"
	if err := os.WriteFile(goodFile, []byte("function hello() { return 'hi'; }"), 0644); err != nil {
		t.Fatal(err)
	}
	vm.LoadJSPaths([]string{"good.js"}, dir)
	assert.Equal(t, initialCount+1, len(vm.programs), "should load valid .js file")
}

// ---------------------------------------------------------------------------
// 13. TykStorage* bindings — bounded atomic storage for JS plugins
// ---------------------------------------------------------------------------

func TestGoja_StorageBindings(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)

	// Unique key base so reruns against a shared Redis don't collide.
	base := fmt.Sprintf("goja-store-%d", time.Now().UnixNano())
	run := func(t *testing.T, js string) string {
		t.Helper()
		result, err := vm.Run(js)
		require.NoError(t, err)
		return result
	}

	t.Run("set get roundtrip", func(t *testing.T) {
		assert.Equal(t, "hello", run(t, fmt.Sprintf(`TykStorageSet(%[1]q, "hello", 0); TykStorageGet(%[1]q)`, base+"-rt")))
	})

	t.Run("missing key returns null", func(t *testing.T) {
		assert.Equal(t, "null", run(t, fmt.Sprintf(`String(TykStorageGet(%q))`, base+"-missing")))
	})

	t.Run("ttl", func(t *testing.T) {
		js := fmt.Sprintf(`TykStorageSet(%[1]q, "v", 30); TykStorageTTL(%[1]q)`, base+"-ttl")
		ttl, err := strconv.ParseInt(run(t, js), 10, 64)
		require.NoError(t, err)
		assert.True(t, ttl > 0 && ttl <= 30, "expected 0 < ttl <= 30, got %d", ttl)
		// No expiry → -1; missing key → -2 (redis semantics).
		assert.Equal(t, "-1", run(t, fmt.Sprintf(`TykStorageSet(%[1]q, "v", 0); TykStorageTTL(%[1]q)`, base+"-nottl")))
		assert.Equal(t, "-2", run(t, fmt.Sprintf(`TykStorageTTL(%q)`, base+"-ttl-missing")))
	})

	t.Run("del", func(t *testing.T) {
		js := fmt.Sprintf(`TykStorageSet(%[1]q, "v", 0); TykStorageDel(%[1]q); String(TykStorageGet(%[1]q))`, base+"-del")
		assert.Equal(t, "null", run(t, js))
	})

	t.Run("setnx claims once", func(t *testing.T) {
		key := base + "-nx"
		assert.Equal(t, "true", run(t, fmt.Sprintf(`String(TykStorageSetNX(%q, "first", 30))`, key)))
		assert.Equal(t, "false", run(t, fmt.Sprintf(`String(TykStorageSetNX(%q, "second", 30))`, key)))
		assert.Equal(t, "first", run(t, fmt.Sprintf(`TykStorageGet(%q)`, key)))
	})

	t.Run("incr returns string and applies ttl on first increment only", func(t *testing.T) {
		key := base + "-incr"
		assert.Equal(t, "string", run(t, fmt.Sprintf(`typeof TykStorageIncr(%q, 30)`, key)))
		assert.Equal(t, "2", run(t, fmt.Sprintf(`TykStorageIncr(%q, 30)`, key)))
		ttl, err := strconv.ParseInt(run(t, fmt.Sprintf(`TykStorageTTL(%q)`, key)), 10, 64)
		require.NoError(t, err)
		assert.True(t, ttl > 0 && ttl <= 30, "expected TTL from first increment, got %d", ttl)
	})

	t.Run("caps are enforced and catchable", func(t *testing.T) {
		// Oversized key → thrown error surfaces via vm.Run.
		_, err := vm.Run(`TykStorageSet(Array(300).join("k"), "v", 0)`)
		assert.Error(t, err)
		// Oversized value → catchable in JS with try/catch.
		js := `try { TykStorageSet("cap-key", Array(70000).join("v"), 0); "no-throw" } catch (e) { "threw" }`
		assert.Equal(t, "threw", run(t, js))
	})

	t.Run("keys are namespaced under jsvm-store prefix", func(t *testing.T) {
		// A plugin key named like a session key must not escape the prefix.
		run(t, `TykStorageSet("apikey-foo", "trapped", 0); "ok"`)
		rc := storage.RedisCluster{ConnectionHandler: ts.Gw.StorageConnectionHandler}
		val, err := rc.GetRawKey("jsvm-store:apikey-foo")
		require.NoError(t, err)
		assert.Equal(t, "trapped", val)
		_, err = rc.GetRawKey("apikey-foo")
		assert.ErrorIs(t, err, storage.ErrKeyNotFound)
	})

	t.Run("nil store throws instead of failing silently", func(t *testing.T) {
		vm.DeInit()
		defer vm.Init(nil, log.NewEntry(), ts.Gw)
		h := &JSVMAPIHelper{Log: log.NewEntry()}
		_, _, err := h.StorageGet("any")
		assert.ErrorIs(t, err, errJSVMStoreUnavailable)
	})
}

// TestGoja_StorageBindings_Contention verifies the atomicity contract under
// concurrency: exactly one SetNX winner, and Incr never loses an update.
func TestGoja_StorageBindings_Contention(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, log.NewEntry(), ts.Gw)

	const n = 50

	t.Run("setnx has exactly one winner", func(t *testing.T) {
		key := fmt.Sprintf("goja-store-race-nx-%d", time.Now().UnixNano())
		var wg sync.WaitGroup
		var claimed, failed int64
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, err := vm.Run(fmt.Sprintf(`String(TykStorageSetNX(%q, "owner", 60))`, key))
				if err != nil {
					atomic.AddInt64(&failed, 1)
					return
				}
				if result == "true" {
					atomic.AddInt64(&claimed, 1)
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, int64(0), failed, "no SetNX call should error")
		assert.Equal(t, int64(1), claimed, "exactly one goroutine should claim the key")
	})

	t.Run("incr counts every update", func(t *testing.T) {
		key := fmt.Sprintf("goja-store-race-incr-%d", time.Now().UnixNano())
		var wg sync.WaitGroup
		var failed int64
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := vm.Run(fmt.Sprintf(`TykStorageIncr(%q, 60)`, key)); err != nil {
					atomic.AddInt64(&failed, 1)
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, int64(0), failed, "no Incr call should error")
		final, err := vm.Run(fmt.Sprintf(`TykStorageGet(%q)`, key))
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(n), final)
	})
}
