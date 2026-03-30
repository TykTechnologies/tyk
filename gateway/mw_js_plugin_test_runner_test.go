package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// helper: post a pluginTestRunnerRequest to the handler and decode the response.
func runPluginTestRunner(t *testing.T, gw *Gateway, req pluginTestRunnerRequest) (int, pluginTestRunnerResponse) {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/tyk/plugins/test", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	gw.pluginTestHandler(rec, httpReq)

	var resp pluginTestRunnerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return rec.Code, resp
}

// ---------------------------------------------------------------------------
// 1. Pre hook — plugin adds SetHeaders["X-Test"]
// ---------------------------------------------------------------------------

func TestPluginTestRunner_PreHookSetHeader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session) {
	request.SetHeaders["X-Test"] = "hello";
	return p.ReturnData(request, {});
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.RequestAfter)
	assert.Equal(t, "hello", resp.RequestAfter.SetHeaders["X-Test"])
}

// ---------------------------------------------------------------------------
// 1b. Pre hook — session input should be ignored (matches production behavior)
// ---------------------------------------------------------------------------

func TestPluginTestRunner_PreHookIgnoresSession(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session) {
	log(JSON.stringify(session));
	return p.ReturnData(request, {});
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
		Session: json.RawMessage(`{"rate": 999, "org_id": "should-be-ignored"}`),
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotEmpty(t, resp.Logs)
	// The logged session should be an empty/zero session, not the supplied one
	assert.NotContains(t, resp.Logs[0].Message, "should-be-ignored")
}

// ---------------------------------------------------------------------------
// 2. Response hook — plugin modifies response.Body
// ---------------------------------------------------------------------------

func TestPluginTestRunner_ResponseHookModifiesBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessResponse(function(request, response, session) {
	response.Body = "modified body";
	return p.ReturnResponseData(response, {});
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "response",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
		Response: &pluginTestRunnerMockResp{
			StatusCode: 200,
			Body:       "original body",
		},
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.ResponseAfter)
	assert.Equal(t, "modified body", resp.ResponseAfter.Body)
}

// ---------------------------------------------------------------------------
// 3. Auth check — ReturnAuthData populates session_after
// ---------------------------------------------------------------------------

func TestPluginTestRunner_AuthCheckReturnAuthData(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session) {
	var thisSession = {
		"allowance": 100, "rate": 100, "per": 1,
		"quota_max": -1, "quota_renews": 1906121006,
		"expires": 1906121006, "access_rights": {},
		"org_id": "testorg"
	};
	return p.ReturnAuthData(request, thisSession);
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "auth_check",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method:  "GET",
			Path:    "/secure",
			Headers: map[string][]string{"Authorization": {"Bearer token"}},
		},
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotNil(t, resp.SessionAfter, "session_after should be populated by ReturnAuthData")

	// SessionAfter is decoded as a map from JSON; verify org_id made it through.
	sessionMap, ok := resp.SessionAfter.(map[string]any)
	require.True(t, ok, "session_after should be a map, got %T", resp.SessionAfter)
	assert.Equal(t, "testorg", sessionMap["org_id"])
}

// ---------------------------------------------------------------------------
// 4. Log capture — log("hello") appears in logs
// ---------------------------------------------------------------------------

func TestPluginTestRunner_LogCapture(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session) {
	log("hello");
	return p.ReturnData(request, {});
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotEmpty(t, resp.Logs, "expected at least one log entry")
	assert.Equal(t, "hello", resp.Logs[0].Message)
}

// ---------------------------------------------------------------------------
// 5. Syntax error — invalid code returns error.type == "syntax"
// ---------------------------------------------------------------------------

func TestPluginTestRunner_SyntaxError(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     "var x = {",
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
	})

	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "syntax", resp.Error.Type)
}

// ---------------------------------------------------------------------------
// 6. Timeout — while(true){} returns error.type == "timeout"
// ---------------------------------------------------------------------------

func TestPluginTestRunner_Timeout(t *testing.T) {
	ts := StartTest(func(c *config.Config) {
		c.JSVMTimeout = 1 // 1 second
	})
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session) {
	while(true) {}
	return p.ReturnData(request, {});
});`

	req := pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
	}

	done := make(chan struct{})
	var status int
	var resp pluginTestRunnerResponse

	go func() {
		status, resp = runPluginTestRunner(t, ts.Gw, req)
		close(done)
	}()

	select {
	case <-done:
		// Completed within deadline — verify the result.
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return within timeout + 1s")
	}

	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "timeout", resp.Error.Type)
}

// ---------------------------------------------------------------------------
// 7. No middleware registered — descriptive error
// ---------------------------------------------------------------------------

func TestPluginTestRunner_NoMiddlewareRegistered(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Valid JS that does NOT call NewProcessRequest or NewProcessResponse.
	code := `var x = 42;`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
	})

	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "did not register")
}

// ---------------------------------------------------------------------------
// 8. config_data — plugin reads config.config_data.foo and logs it
// ---------------------------------------------------------------------------

func TestPluginTestRunner_ConfigData(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessRequest(function(request, session, config) {
	log(config.config_data.foo);
	return p.ReturnData(request, {});
});`

	status, resp := runPluginTestRunner(t, ts.Gw, pluginTestRunnerRequest{
		Code:     code,
		HookType: "pre",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
		ConfigData: map[string]any{"foo": "bar"},
	})

	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, resp.Error)
	require.NotEmpty(t, resp.Logs, "expected config_data.foo to be logged")
	assert.Equal(t, "bar", resp.Logs[0].Message)
}

// ---------------------------------------------------------------------------
// 9. Response hook without response field — returns 400
// ---------------------------------------------------------------------------

func TestPluginTestRunner_ResponseHookRequiresResponse(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	code := `
var p = new TykJS.TykMiddleware.NewMiddleware({});
p.NewProcessResponse(function(request, response, session) {
	return p.ReturnResponseData(response, {});
});`

	body, err := json.Marshal(pluginTestRunnerRequest{
		Code:     code,
		HookType: "response",
		OrgID:    "testorg",
		Request: pluginTestRunnerMockReq{
			Method: "GET",
			Path:   "/test",
		},
		// No Response field
	})
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/tyk/plugins/test", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ts.Gw.pluginTestHandler(rec, httpReq)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "response is required")
}

// ---------------------------------------------------------------------------
// 10. Invalid session JSON — returns 400
// ---------------------------------------------------------------------------

func TestPluginTestRunner_InvalidSessionJSON(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	body, err := json.Marshal(pluginTestRunnerRequest{
		Code:     `var p = new TykJS.TykMiddleware.NewMiddleware({}); p.NewProcessRequest(function(r, s) { return p.ReturnData(r, {}); });`,
		HookType: "post",
		OrgID:    "testorg",
		Request:  pluginTestRunnerMockReq{Method: "GET", Path: "/test"},
		Session:  json.RawMessage(`{"rate": "not-a-number"}`),
	})
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/tyk/plugins/test", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ts.Gw.pluginTestHandler(rec, httpReq)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid session JSON")
}
