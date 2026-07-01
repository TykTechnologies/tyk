package gateway

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

// This file holds regression tests that lock in behaviour specific to the
// otto -> goja migration. They complement the functional parity tests in
// mw_js_plugin_goja_test.go (which run ES5 source on both engines) by adding
// oracles that would FAIL if the javascript driver silently routed back to
// otto, or if a plugin failure stopped failing safe.

// TestGoja_StopProxyWhenFail asserts the goja driver fails safe: a plugin that
// cannot be loaded or that throws at runtime must make the request return 500,
// never silently pass the request through. This mirrors the otto-only
// TestJSVM_StopProxyWhenFail for the javascript (goja) driver.
func TestGoja_StopProxyWhenFail(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("missing middleware file returns 500", func(t *testing.T) {
		const apiID = "goja-failsafe-missing"
		api := BuildAPI(func(spec *APISpec) {
			spec.APIID = apiID
			spec.Proxy.ListenPath = "/" + apiID + "/"
			spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
			spec.CustomMiddleware.Pre = []apidef.MiddlewareDefinition{{
				Name: "nope",
				Path: "non-existing.js",
			}}
		})[0]
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/" + apiID + "/get", Code: http.StatusInternalServerError,
			BodyMatch: http.StatusText(http.StatusInternalServerError),
		})
	})

	t.Run("handler that throws at runtime returns 500", func(t *testing.T) {
		const apiID = "goja-failsafe-throw"
		const throwJS = `
var throwMid = new TykJS.TykMiddleware.NewMiddleware({});
throwMid.NewProcessRequest(function(request, session) {
	throw new Error("boom");
});`
		ts.RegisterJSFileMiddleware(apiID, map[string]string{"throw.js": throwJS})
		api := BuildAPI(func(spec *APISpec) {
			spec.APIID = apiID
			spec.Proxy.ListenPath = "/" + apiID + "/"
			spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
			spec.CustomMiddleware.Pre = []apidef.MiddlewareDefinition{{
				Name: "throwMid",
				Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/throw.js",
			}}
		})[0]
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/" + apiID + "/get", Code: http.StatusInternalServerError,
			BodyMatch: http.StatusText(http.StatusInternalServerError),
		})
	})

	t.Run("inline code with a syntax error does not serve traffic", func(t *testing.T) {
		const apiID = "goja-failsafe-syntax"
		// Base64 of deliberately broken JS — must not compile.
		badCode := base64.StdEncoding.EncodeToString([]byte("var handler = new TykJS.TykMiddleware.NewMiddleware({}); function {{{"))
		api := BuildAPI(func(spec *APISpec) {
			spec.APIID = apiID
			spec.Proxy.ListenPath = "/" + apiID + "/"
			spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
			spec.CustomMiddleware.Pre = []apidef.MiddlewareDefinition{{
				Name: "handler",
				Code: badCode,
			}}
		})[0]
		ts.Gw.LoadAPI(api)
		_, _ = ts.Run(t, test.TestCase{
			Path: "/" + apiID + "/get", Code: http.StatusInternalServerError,
			BodyMatch: http.StatusText(http.StatusInternalServerError),
		})
	})
}

// TestGoja_EngineDivergence_OttoRejectsES6_GojaAccepts is the routing oracle for
// the migration. The same ES6 source (an arrow function — ES6, which otto's
// ES5.1 parser cannot read but goja can) must FAIL on otto and SUCCEED on goja.
// Every other JS test runs ES5 source on both engines, so a regression that
// silently routed the javascript driver back to otto would keep them all green;
// this is the one test that would not.
func TestGoja_EngineDivergence_OttoRejectsES6_GojaAccepts(t *testing.T) {
	const es6JS = `
var es6Mid = new TykJS.TykMiddleware.NewMiddleware({});
es6Mid.NewProcessRequest(function(request, session) {
	var double = (x) => x * 2;
	request.SetHeaders["X-Es6-Result"] = String(double(21));
	return es6Mid.ReturnData(request, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "es6-oracle-" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{"es6.js": es6JS})
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/" + apiID + "/"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Pre: []apidef.MiddlewareDefinition{{
						Name: "es6Mid",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/es6.js",
					}},
				}
			})

			if driver == apidef.JavaScriptDriver {
				// goja parses the arrow function and runs it.
				ts.Run(t, test.TestCase{
					Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Es6-Result":"42"`,
				})
			} else {
				// otto cannot parse the arrow function, so the plugin never loads
				// and the request fails safe rather than running ES6.
				ts.Run(t, test.TestCase{
					Path: "/" + apiID + "/get", Code: http.StatusInternalServerError,
				})
			}
		})
	}
}

// TestGoja_TykMakeHttpRequest_EndToEnd drives TykMakeHttpRequest through the full
// request path on the goja driver (not a direct VM.Run), proving the JS->Go JSON
// bridge marshals the outbound request and decodes {Code,Body,Headers} back into
// JS. Existing coverage only exercises the bridge via GojaJSVM.Run directly.
func TestGoja_TykMakeHttpRequest_EndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	}))
	defer upstream.Close()

	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-http-e2e"
	js := `
var httpMid = new TykJS.TykMiddleware.NewMiddleware({});
httpMid.NewProcessRequest(function(request, session) {
	var raw = TykMakeHttpRequest(JSON.stringify({
		Method: "GET",
		Domain: "` + upstream.URL + `",
		Resource: "/"
	}));
	var resp = JSON.parse(raw);
	request.SetHeaders["X-Upstream-Code"] = String(resp.Code);
	request.SetHeaders["X-Upstream-Body"] = resp.Body;
	return httpMid.ReturnData(request, {});
});`

	ts.RegisterJSFileMiddleware(apiID, map[string]string{"http.js": js})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Pre: []apidef.MiddlewareDefinition{{
				Name: "httpMid",
				Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/http.js",
			}},
		}
	})

	// The default test upstream echoes request headers into the response body,
	// so the values the plugin set from the outbound response are observable.
	ts.Run(t,
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Upstream-Code":"200"`},
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Upstream-Body":"pong"`},
	)
}

// TestGoja_UnderscoreLibraryAbsence pins the one documented breaking change in
// the migration: otto auto-loaded underscore.js as the global _, goja does not.
// A plugin that relied on _ silently works on otto and must visibly not on goja.
func TestGoja_UnderscoreLibraryAbsence(t *testing.T) {
	const js = `
var underscoreMid = new TykJS.TykMiddleware.NewMiddleware({});
underscoreMid.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Underscore-Type"] = typeof _;
	return underscoreMid.ReturnData(request, {});
});`

	wantType := map[apidef.MiddlewareDriver]string{
		apidef.OttoDriver:       "function",
		apidef.JavaScriptDriver: "undefined",
	}

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "underscore-" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{"u.js": js})
			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/" + apiID + "/"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Pre: []apidef.MiddlewareDefinition{{
						Name: "underscoreMid",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/u.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path:      "/" + apiID + "/get",
				Code:      http.StatusOK,
				BodyMatch: `"X-Underscore-Type":"` + wantType[driver] + `"`,
			})
		})
	}
}

// gojaInlineMarker base64-encodes a minimal inline plugin that stamps a marker
// header, used by the inline-code tests below.
func gojaInlineMarker(header, value string) string {
	js := `var handler = new TykJS.TykMiddleware.NewMiddleware({});
handler.NewProcessRequest(function(request, session) {
	request.SetHeaders["` + header + `"] = "` + value + `";
	return handler.ReturnData(request, {});
});`
	return base64.StdEncoding.EncodeToString([]byte(js))
}

// TestGoja_HotReloadInlineCode asserts the documented reload contract: changing
// an API's inline `code` and reloading recompiles it — the gateway serves the
// NEW behaviour, never stale compiled code. There is no on-disk plugin cache to
// invalidate, so a regression here would silently keep running the old source.
func TestGoja_HotReloadInlineCode(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-inline-reload"
	api := BuildAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.CustomMiddleware.Driver = apidef.JavaScriptDriver
		spec.CustomMiddleware.Pre = []apidef.MiddlewareDefinition{{
			Name: "handler",
			Code: gojaInlineMarker("X-Reload-Marker", "v1"),
		}}
	})[0]

	ts.Gw.LoadAPI(api)
	ts.Run(t, test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Reload-Marker":"v1"`})

	// Swap the inline source and reload — must recompile, not serve v1.
	api.CustomMiddleware.Pre[0].Code = gojaInlineMarker("X-Reload-Marker", "v2")
	ts.Gw.LoadAPI(api)
	ts.Run(t, test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Reload-Marker":"v2"`})
}

// TestGoja_InlineHandlersSameNameCoexist proves goja's per-entry handler
// isolation: two inline plugins on the same API that both declare `var handler`
// (one pre, one post) must BOTH run. On the legacy otto engine these would share
// one global namespace and the last loaded would clobber the first.
func TestGoja_InlineHandlersSameNameCoexist(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-isolation"
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Pre:    []apidef.MiddlewareDefinition{{Name: "handler", Code: gojaInlineMarker("X-From-Pre", "yes")}},
			Post:   []apidef.MiddlewareDefinition{{Name: "handler", Code: gojaInlineMarker("X-From-Post", "yes")}},
		}
	})

	// Both handlers ran if both markers reach the (header-echoing) upstream.
	ts.Run(t,
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-From-Pre":"yes"`},
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-From-Post":"yes"`},
	)
}

// TestGoja_FreshRuntimePerRequest pins the documented runtime model: each request
// executes against fresh global state, so a global written by one request is not
// visible to the next. Each request must report seeing the counter at 0.
func TestGoja_FreshRuntimePerRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-fresh"
	const js = `
var freshMid = new TykJS.TykMiddleware.NewMiddleware({});
freshMid.NewProcessRequest(function(request, session) {
	if (typeof globalThis.__leak === "undefined") { globalThis.__leak = 0; }
	request.SetHeaders["X-Seen"] = String(globalThis.__leak);
	globalThis.__leak = globalThis.__leak + 1;
	return freshMid.ReturnData(request, {});
});`

	ts.RegisterJSFileMiddleware(apiID, map[string]string{"fresh.js": js})
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Pre:    []apidef.MiddlewareDefinition{{Name: "freshMid", Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/fresh.js"}},
		}
	})

	ts.Run(t,
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Seen":"0"`},
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-Seen":"0"`},
	)
}

// TestGoja_SessionMetaPassedBetweenPostHooks proves the multi-plugin handoff
// pattern: an earlier post hook writes session.meta_data (via ReturnData's second
// argument) and a later post hook on the same request reads it back. This is how
// plugins share state within a request, and it had no regression test.
func TestGoja_SessionMetaPassedBetweenPostHooks(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-session-handoff"

	const writerJS = `
var writer = new TykJS.TykMiddleware.NewMiddleware({});
writer.NewProcessRequest(function(request, session) {
	return writer.ReturnData(request, {handoff: "A-to-B"});
});`
	const readerJS = `
var reader = new TykJS.TykMiddleware.NewMiddleware({});
reader.NewProcessRequest(function(request, session) {
	var v = (session && session.meta_data) ? session.meta_data.handoff : "";
	request.SetHeaders["X-Handoff"] = String(v);
	return reader.ReturnData(request, {});
});`

	ts.RegisterJSFileMiddleware(apiID, map[string]string{
		"writer.js": writerJS,
		"reader.js": readerJS,
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.OrgID = "default"
		spec.Proxy.ListenPath = "/" + apiID + "/"
		spec.UseKeylessAccess = false
		spec.UseStandardAuth = true
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Post: []apidef.MiddlewareDefinition{
				{Name: "writer", Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/writer.js", RequireSession: true},
				{Name: "reader", Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/reader.js", RequireSession: true},
			},
		}
	})

	_, key := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			apiID: {APIID: apiID, Versions: []string{"Default"}},
		}
	})

	ts.Run(t, test.TestCase{
		Path:      "/" + apiID + "/get",
		Headers:   map[string]string{"Authorization": key},
		Code:      http.StatusOK,
		BodyMatch: `"X-Handoff":"A-to-B"`,
	})
}

// TestGoja_BundleReplacesInlineMiddleware locks in the documented precedence:
// when an API references a bundle, the bundle's manifest REPLACES the API's
// inline custom_middleware section entirely. The bundle's plugin must run and
// the inline `code` plugin must be ignored, so an operator can't accidentally
// run both.
func TestGoja_BundleReplacesInlineMiddleware(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	const apiID = "goja-bundle-vs-inline"
	bundle := ts.RegisterBundle("bundle_replaces_inline", map[string]string{
		"manifest.json": `{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "javascript",
		        "pre": [{"name": "bundlePre", "path": "pre.js"}]
		    },
		    "checksum": "d41d8cd98f00b204e9800998ecf8427e"
		}`,
		"pre.js": `
var bundlePre = new TykJS.TykMiddleware.NewMiddleware({});
bundlePre.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-From-Bundle"] = "yes";
	return bundlePre.ReturnData(request, {});
});`,
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Proxy.ListenPath = "/" + apiID + "/"
		// Inline middleware declared on the API definition...
		spec.CustomMiddleware = apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
			Pre:    []apidef.MiddlewareDefinition{{Name: "handler", Code: gojaInlineMarker("X-From-Inline", "yes")}},
		}
		// ...plus a bundle, which must replace the inline section entirely.
		spec.CustomMiddlewareBundle = bundle
	})

	ts.Run(t,
		// The bundle's plugin runs.
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyMatch: `"X-From-Bundle":"yes"`},
		// The inline plugin was replaced, so its marker never reaches upstream.
		test.TestCase{Path: "/" + apiID + "/get", Code: http.StatusOK, BodyNotMatch: `"X-From-Inline"`},
	)
}
