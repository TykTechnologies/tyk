package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

// pluginTestRunnerRequest is the request body for POST /tyk/plugins/test.
// org_id and api_id are always injected by the dashboard — clients cannot override them.
type pluginTestRunnerRequest struct {
	Code       string                 `json:"code"`
	HookType   string                 `json:"hook_type"`
	OrgID      string                 `json:"org_id"`
	APIID      string                 `json:"api_id"`
	Request    pluginTestRunnerMockReq   `json:"request"`
	Response   *pluginTestRunnerMockResp `json:"response,omitempty"`
	Session    json.RawMessage        `json:"session,omitempty"`
	ConfigData map[string]any `json:"config_data,omitempty"`
}

type pluginTestRunnerMockReq struct {
	Method     string              `json:"Method"`
	Path       string              `json:"Path"`
	URL        string              `json:"URL"`        // populated by handler if empty
	RequestURI string              `json:"RequestURI"` // populated by handler if empty
	Headers    map[string][]string `json:"Headers"`
	Body       string              `json:"Body"`
	Params     map[string][]string `json:"Params"`
	Scheme     string              `json:"Scheme"`
}

type pluginTestRunnerMockResp struct {
	StatusCode int                 `json:"StatusCode"`
	Body       string              `json:"Body"`
	Headers    map[string][]string `json:"Headers"`
}

type testRunnerLog struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	Time    string `json:"time"`
}

type testRunnerError struct {
	Message string `json:"message"`
	Type    string `json:"type"` // syntax | timeout | runtime
}

// testRunnerRequestAfter is the modifications the plugin made to the request,
// extracted from VMReturnObject and decoded for display.
type testRunnerRequestAfter struct {
	SetHeaders      map[string]string `json:"SetHeaders"`
	DeleteHeaders   []string          `json:"DeleteHeaders"`
	AddParams       map[string]string `json:"AddParams"`
	DeleteParams    []string          `json:"DeleteParams"`
	Body            string            `json:"Body"`
	ReturnOverrides ReturnOverrides   `json:"ReturnOverrides"`
}

type pluginTestRunnerResponse struct {
	Logs           []testRunnerLog           `json:"logs"`
	RequestBefore  *pluginTestRunnerMockReq  `json:"request_before,omitempty"`
	RequestAfter   *testRunnerRequestAfter   `json:"request_after,omitempty"`
	ResponseBefore *pluginTestRunnerMockResp `json:"response_before,omitempty"`
	ResponseAfter  *MiniResponseObject    `json:"response_after,omitempty"`
	SessionAfter   any            `json:"session_after,omitempty"`
	Error          *testRunnerError          `json:"error,omitempty"`
	ExecutionMs    int64                  `json:"execution_ms"`
}

var validHookTypes = map[string]bool{
	"pre":           true,
	"post":          true,
	"post_key_auth": true,
	"auth_check":    true,
	"response":      true,
}

// testRunnerTrackerJS patches NewProcessRequest/NewProcessResponse to capture
// the middleware instance regardless of what variable name the user chose.
const testRunnerTrackerJS = `
var __sandboxMiddleware = null;
(function() {
	var _origReq = TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessRequest;
	TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessRequest = function(cb) {
		_origReq.call(this, cb);
		__sandboxMiddleware = this;
	};
	var _origResp = TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessResponse;
	TykJS.TykMiddleware.NewMiddleware.prototype.NewProcessResponse = function(cb) {
		_origResp.call(this, cb);
		__sandboxMiddleware = this;
	};
})();
`

// pluginTestHandler runs user-supplied JS code against a mock request/response
// using the real gateway goja engine. All bindings are live (TykMakeHttpRequest,
// key CRUD, etc.) — this is not an isolated sandbox, it's a real gateway execution.
//
// Route: POST /tyk/plugins/test (protected by x-tyk-authorization)
func (gw *Gateway) pluginTestHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	// 1. Parse request body
	var req pluginTestRunnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}

	// 2. Validate required fields
	if strings.TrimSpace(req.Code) == "" {
		writeJSON(http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	if !validHookTypes[req.HookType] {
		writeJSON(http.StatusBadRequest, map[string]string{"error": "invalid hook_type: must be one of pre, post, post_key_auth, auth_check, response"})
		return
	}
	if strings.TrimSpace(req.OrgID) == "" {
		writeJSON(http.StatusBadRequest, map[string]string{"error": "org_id is required"})
		return
	}
	if req.HookType == "response" && req.Response == nil {
		writeJSON(http.StatusBadRequest, map[string]string{"error": "response is required for response hooks"})
		return
	}

	// 3. Build minimal APISpec and initialise GojaJSVM via the real Init() path.
	// This loads coreJS, TykJSPath, TykJsResponse, and sets timeout from config.
	spec := minimalTestRunnerAPISpec(&req)
	jsvm := &GojaJSVM{}
	jsvm.Init(spec, logrus.NewEntry(log), gw)
	if !jsvm.Initialized() {
		writeJSON(http.StatusInternalServerError, map[string]string{"error": "failed to initialize JavaScript VM"})
		return
	}

	// 4. Get test runner runtime: all programs replayed, real bindings, log captured
	logs := make([]testRunnerLog, 0)
	vm := jsvm.TestRunnerRuntime(&logs)

	// 5. Inject tracker to capture middleware instance
	if _, err := vm.RunString(testRunnerTrackerJS); err != nil {
		writeJSON(http.StatusInternalServerError, map[string]string{"error": "failed to inject test runner tracker: " + err.Error()})
		return
	}

	// 6. Compile — catches syntax errors without executing
	compiled, err := goja.Compile("user-plugin", req.Code, false)
	if err != nil {
		writeJSON(http.StatusOK, pluginTestRunnerResponse{
			Logs:  logs,
			Error: &testRunnerError{Message: err.Error(), Type: "syntax"},
		})
		return
	}

	// 7. Execute top-level code (defines middleware, registers handlers)
	if _, err := vm.RunProgram(compiled); err != nil {
		writeJSON(http.StatusOK, pluginTestRunnerResponse{
			Logs:  logs,
			Error: &testRunnerError{Message: err.Error(), Type: "runtime"},
		})
		return
	}

	// 8. Verify middleware was registered
	mwVal := vm.Get("__sandboxMiddleware")
	if mwVal == nil || goja.IsNull(mwVal) || goja.IsUndefined(mwVal) {
		writeJSON(http.StatusOK, pluginTestRunnerResponse{
			Logs:  logs,
			Error: &testRunnerError{Message: "plugin did not register a request or response handler via NewProcessRequest/NewProcessResponse", Type: "runtime"},
		})
		return
	}

	// 9. Build JSON for request, session, and config
	mockReqObj := buildTestRunnerMiniRequest(&req)
	requestAsJSON, err := json.Marshal(mockReqObj)
	if err != nil {
		writeJSON(http.StatusInternalServerError, map[string]string{"error": "failed to encode mock request"})
		return
	}

	var session user.SessionState
	if len(req.Session) > 0 {
		if err := json.Unmarshal(req.Session, &session); err != nil {
			writeJSON(http.StatusBadRequest, map[string]string{"error": "invalid session JSON: " + err.Error()})
			return
		}
	}
	// Pre and auth_check hooks receive empty sessions in production
	// (api_loader.go:423, mw_js_plugin.go:179). Honor that here.
	if req.HookType == "pre" || req.HookType == "auth_check" {
		session = user.SessionState{}
	}
	sessionAsJSON, _ := json.Marshal(session)
	configAsJSON := specToJson(spec)

	// Build request_before for display (using the resolved URL/RequestURI)
	requestBefore := pluginTestRunnerMockReq{
		Method:     req.Request.Method,
		Path:       req.Request.Path,
		URL:        mockReqObj.URL,
		RequestURI: mockReqObj.RequestURI,
		Headers:    req.Request.Headers,
		Body:       req.Request.Body,
		Params:     req.Request.Params,
		Scheme:     req.Request.Scheme,
	}

	// 10. Set interrupt timer
	timer := time.AfterFunc(jsvm.Timeout, func() { vm.Interrupt("timeout") })
	defer timer.Stop()

	t1 := time.Now()

	runnerResp := pluginTestRunnerResponse{
		RequestBefore: &requestBefore,
	}

	if req.HookType == "response" {
		gw.runTestRunnerResponseHook(vm, &req, requestAsJSON, sessionAsJSON, configAsJSON, t1, &runnerResp)
	} else {
		gw.runTestRunnerRequestHook(vm, &req, requestAsJSON, sessionAsJSON, configAsJSON, t1, &runnerResp)
	}

	runnerResp.Logs = logs
	writeJSON(http.StatusOK, runnerResp)
}

func (gw *Gateway) runTestRunnerRequestHook(
	vm *goja.Runtime,
	req *pluginTestRunnerRequest,
	requestAsJSON, sessionAsJSON []byte,
	configAsJSON string,
	t1 time.Time,
	runnerResp *pluginTestRunnerResponse,
) {
	expr := fmt.Sprintf("__sandboxMiddleware.DoProcessRequest(%s, %s, %s)", requestAsJSON, sessionAsJSON, configAsJSON)
	retVal, err := vm.RunString(expr)
	runnerResp.ExecutionMs = time.Since(t1).Milliseconds()

	if err != nil {
		runnerResp.Error = &testRunnerError{Message: err.Error(), Type: classifyTestRunnerError(err)}
		return
	}

	var retObj VMReturnObject
	if err := json.Unmarshal([]byte(retVal.String()), &retObj); err != nil {
		runnerResp.Error = &testRunnerError{Message: "failed to parse request hook return: " + err.Error(), Type: "runtime"}
		return
	}

	reqAfter := &testRunnerRequestAfter{
		SetHeaders:      retObj.Request.SetHeaders,
		DeleteHeaders:   retObj.Request.DeleteHeaders,
		AddParams:       retObj.Request.AddParams,
		DeleteParams:    retObj.Request.DeleteParams,
		Body:            string(retObj.Request.Body), // auto-decoded from base64 by json.Unmarshal
		ReturnOverrides: retObj.Request.ReturnOverrides,
	}
	runnerResp.RequestAfter = reqAfter

	// session_after semantics: auth_check → full Session; post/post_key_auth → SessionMeta deltas
	switch req.HookType {
	case "auth_check":
		runnerResp.SessionAfter = retObj.Session
	case "post", "post_key_auth":
		if len(retObj.SessionMeta) > 0 {
			runnerResp.SessionAfter = retObj.SessionMeta
		}
	}
}

func (gw *Gateway) runTestRunnerResponseHook(
	vm *goja.Runtime,
	req *pluginTestRunnerRequest,
	requestAsJSON, sessionAsJSON []byte,
	configAsJSON string,
	t1 time.Time,
	runnerResp *pluginTestRunnerResponse,
) {
	runnerResp.ResponseBefore = req.Response
	runnerResp.RequestBefore = nil // response hooks don't surface the request before

	mockResp := MiniResponseObject{
		StatusCode:    req.Response.StatusCode,
		Body:          req.Response.Body,
		Headers:       req.Response.Headers,
		SetHeaders:    map[string]string{},
		DeleteHeaders: []string{},
	}
	responseAsJSON, _ := json.Marshal(mockResp)

	// Response hooks receive nil body on the request object (matches mw_js_plugin_response.go:123)
	var reqForRespObj MiniRequestObject
	_ = json.Unmarshal(requestAsJSON, &reqForRespObj)
	reqForRespObj.Body = nil
	reqForRespJSON, _ := json.Marshal(reqForRespObj)

	expr := fmt.Sprintf("__sandboxMiddleware.DoProcessResponse(%s, %s, %s, %s)", responseAsJSON, reqForRespJSON, sessionAsJSON, configAsJSON)
	retVal, err := vm.RunString(expr)
	runnerResp.ExecutionMs = time.Since(t1).Milliseconds()

	if err != nil {
		runnerResp.Error = &testRunnerError{Message: err.Error(), Type: classifyTestRunnerError(err)}
		return
	}

	var retObj VMResponseReturnObject
	if err := json.Unmarshal([]byte(retVal.String()), &retObj); err != nil {
		runnerResp.Error = &testRunnerError{Message: "failed to parse response hook return: " + err.Error(), Type: "runtime"}
		return
	}

	runnerResp.ResponseAfter = &retObj.Response
	if len(retObj.SessionMeta) > 0 {
		runnerResp.SessionAfter = retObj.SessionMeta
	}
}

func classifyTestRunnerError(err error) string {
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		return "timeout"
	}
	return "runtime"
}

// buildTestRunnerMiniRequest constructs a MiniRequestObject from the test runner request.
// Body is []byte so json.Marshal will base64-encode it (matching DoProcessRequest expectations).
// URL and RequestURI are synthesised if not supplied by the client.
func buildTestRunnerMiniRequest(req *pluginTestRunnerRequest) MiniRequestObject {
	scheme := req.Request.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := req.Request.Path
	if path == "" {
		path = "/"
	}

	urlStr := req.Request.URL
	if urlStr == "" {
		urlStr = scheme + "://__sandbox__" + path
		if len(req.Request.Params) > 0 {
			urlStr += "?" + url.Values(req.Request.Params).Encode()
		}
	}
	requestURI := req.Request.RequestURI
	if requestURI == "" {
		requestURI = path
		if len(req.Request.Params) > 0 {
			requestURI += "?" + url.Values(req.Request.Params).Encode()
		}
	}

	headers := req.Request.Headers
	if headers == nil {
		headers = map[string][]string{}
	}
	params := req.Request.Params
	if params == nil {
		params = map[string][]string{}
	}

	return MiniRequestObject{
		Headers:        headers,
		SetHeaders:     map[string]string{},
		DeleteHeaders:  []string{},
		Body:           []byte(req.Request.Body),
		URL:            urlStr,
		Params:         params,
		AddParams:      map[string]string{},
		ExtendedParams: map[string][]string{},
		DeleteParams:   []string{},
		Method:         req.Request.Method,
		RequestURI:     requestURI,
		Scheme:         scheme,
	}
}

// minimalTestRunnerAPISpec builds the minimal APISpec needed to run a plugin.
// The spec has no proxy, TLS, or middleware config — only what the JS runtime needs.
func minimalTestRunnerAPISpec(req *pluginTestRunnerRequest) *APISpec {
	apiID := req.APIID
	if apiID == "" {
		apiID = "__sandbox__"
	}
	configData := make(map[string]any)
	maps.Copy(configData, req.ConfigData)
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:      apiID,
			OrgID:      req.OrgID,
			ConfigData: configData,
		},
	}
}
