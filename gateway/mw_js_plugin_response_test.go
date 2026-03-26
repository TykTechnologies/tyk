package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestJSResponseMiddleware_HeaderInjection(t *testing.T) {
	const js = `
var respHook = new TykJS.TykMiddleware.NewMiddleware({});

respHook.NewProcessResponse(function(response, request, session, config) {
	response.SetHeaders["X-Response-Modified"] = "true";
	return respHook.ReturnResponseData(response, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "js_resp_hook_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"resp_hook.js": js,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Response: []apidef.MiddlewareDefinition{{
						Name: "respHook",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/resp_hook.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path:         "/test",
				Code:         http.StatusOK,
				HeadersMatch: map[string]string{"X-Response-Modified": "true"},
			})
		})
	}
}

func TestJSResponseMiddleware_BodyModification(t *testing.T) {
	const js = `
var bodyRespHook = new TykJS.TykMiddleware.NewMiddleware({});

bodyRespHook.NewProcessResponse(function(response, request, session, config) {
	response.Body = "custom-response-body";
	return bodyRespHook.ReturnResponseData(response, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "js_resp_body_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"body_hook.js": js,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Response: []apidef.MiddlewareDefinition{{
						Name: "bodyRespHook",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/body_hook.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path:      "/test",
				Code:      http.StatusOK,
				BodyMatch: "custom-response-body",
			})
		})
	}
}

func TestJSResponseMiddleware_StatusCodeModification(t *testing.T) {
	const js = `
var statusRespHook = new TykJS.TykMiddleware.NewMiddleware({});

statusRespHook.NewProcessResponse(function(response, request, session, config) {
	response.StatusCode = 201;
	response.SetHeaders["X-Status-Changed"] = "true";
	return statusRespHook.ReturnResponseData(response, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "js_resp_status_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"status_hook.js": js,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Response: []apidef.MiddlewareDefinition{{
						Name: "statusRespHook",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/status_hook.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path:         "/test",
				Code:         201,
				HeadersMatch: map[string]string{"X-Status-Changed": "true"},
			})
		})
	}
}

func TestJSResponseMiddleware_HeaderDeletion(t *testing.T) {
	const js = `
var delRespHook = new TykJS.TykMiddleware.NewMiddleware({});

delRespHook.NewProcessResponse(function(response, request, session, config) {
	response.DeleteHeaders.push("Content-Type");
	response.SetHeaders["X-Deleted-Content-Type"] = "true";
	return delRespHook.ReturnResponseData(response, {});
});`

	for _, driver := range drivers {
		t.Run(string(driver), func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			apiID := "js_resp_del_" + string(driver)
			ts.RegisterJSFileMiddleware(apiID, map[string]string{
				"del_hook.js": js,
			})

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.APIID = apiID
				spec.Proxy.ListenPath = "/test"
				spec.CustomMiddleware = apidef.MiddlewareSection{
					Driver: driver,
					Response: []apidef.MiddlewareDefinition{{
						Name: "delRespHook",
						Path: ts.Gw.GetConfig().MiddlewarePath + "/" + apiID + "/del_hook.js",
					}},
				}
			})

			ts.Run(t, test.TestCase{
				Path:            "/test",
				Code:            http.StatusOK,
				HeadersMatch:    map[string]string{"X-Deleted-Content-Type": "true"},
				HeadersNotMatch: map[string]string{"Content-Type": ""},
			})
		})
	}
}
