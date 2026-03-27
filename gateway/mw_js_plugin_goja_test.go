package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// drivers runs subtests against both otto and goja to verify identical behaviour.
var drivers = []apidef.MiddlewareDriver{apidef.OttoDriver, apidef.GojaDriver}

// initJSVM initialises the correct JSVM type on the spec for the given driver
// and loads the JS source into it.
func initJSVM(t *testing.T, spec *APISpec, gw *Gateway, driver apidef.MiddlewareDriver, js string) {
	t.Helper()
	spec.CustomMiddleware.Driver = driver

	if driver == apidef.GojaDriver {
		spec.GojaJSVM.Init(spec, logrus.NewEntry(log), gw)
		if err := spec.GojaJSVM.LoadScript(js); err != nil {
			t.Fatalf("failed to load JS into GojaJSVM: %v", err)
		}
	} else {
		spec.JSVM.Init(spec, logrus.NewEntry(log), gw)
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
			_, _ = dynMid.ProcessRequest(nil, req, nil)

			got, _ := io.ReadAll(req.Body)
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

			_, _ = dynMid.ProcessRequest(nil, req, nil)

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
			if driver == apidef.GojaDriver {
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
			_, _ = dynMid.ProcessRequest(nil, r, nil)
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
					Headers:       map[string]string{"Authorization": "wrong"},
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
	gojaVM.Init(nil, logrus.NewEntry(log), ts.Gw)

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
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)
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
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)

	err := vm.LoadScript("function {{{ invalid syntax")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// 12. LoadJSPaths — unsupported extension, missing file, compile error
// ---------------------------------------------------------------------------

func TestGoja_LoadJSPaths(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	vm := GojaJSVM{}
	vm.Init(nil, logrus.NewEntry(log), ts.Gw)

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
