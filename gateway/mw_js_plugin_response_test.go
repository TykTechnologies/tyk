package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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

// ---------------------------------------------------------------------------
// Unit tests for JSResponseMiddleware accessors and error paths
// ---------------------------------------------------------------------------

func TestJSResponseMiddleware_Init_InvalidType(t *testing.T) {
	h := &JSResponseMiddleware{}
	err := h.Init("not a MiddlewareDefinition", nil) //nolint:govet // intentionally passing wrong type
	if err == nil {
		t.Fatal("expected error for invalid middleware definition type")
	}
}

func TestJSResponseMiddleware_Init_Valid(t *testing.T) {
	h := &JSResponseMiddleware{}
	err := h.Init(apidef.MiddlewareDefinition{Name: "testHook"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.hookName != "testHook" {
		t.Fatalf("expected hookName 'testHook', got '%s'", h.hookName)
	}
}

func TestJSResponseMiddleware_Name(t *testing.T) {
	h := &JSResponseMiddleware{}
	if h.Name() != "JSResponseMiddleware" {
		t.Fatalf("expected 'JSResponseMiddleware', got '%s'", h.Name())
	}
}

func TestJSResponseMiddleware_Base(t *testing.T) {
	h := JSResponseMiddleware{}
	b := h.Base()
	if b == nil {
		t.Fatal("expected non-nil BaseTykResponseHandler")
	}
}

// ---------------------------------------------------------------------------
// HandleResponse — error paths
// ---------------------------------------------------------------------------

// TestJSResponseMiddleware_HandleResponse_NoRunner verifies that HandleResponse
// returns an error when no JS runner is initialised on the spec.
func TestJSResponseMiddleware_HandleResponse_NoRunner(t *testing.T) {
	// Fresh spec with no JSVM initialised → GetJSRunner() returns nil.
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}

	h := &JSResponseMiddleware{
		hookName: "testHook",
		spec:     spec,
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("response body")),
	}

	err := h.HandleResponse(nil, res, req, nil)
	assert.Error(t, err)
}
