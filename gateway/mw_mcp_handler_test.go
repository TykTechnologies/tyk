package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	"github.com/TykTechnologies/tyk/apidef"
	oas "github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// makeMCPHandlerSpec builds a minimal *APISpec carrying the MCPProxy
// extension on its OAS.Server. The fixture matches handler_test.go in
// the proxy package: a single loopback source with one tool.
func makeMCPHandlerSpec(t *testing.T) *APISpec {
	t.Helper()
	o := &oas.OAS{}
	o.OpenAPI = "3.1.0"
	o.Info = nil // tolerated for the middleware path; not exercised here
	o.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			MCPProxy: &oas.MCPProxy{
				ProtocolVersion: "2025-06-18",
				Sources: []oas.MCPSource{
					{
						SourceSlug:  "hello-svc",
						BackendMode: "loopback",
						SourceAPIID: "hello-api-id",
						Tools: []oas.MCPToolMapping{
							{
								ToolName:     "hello-svc__get_hello",
								Method:       "GET",
								PathTemplate: "/hello/{id}",
								InputSchema: json.RawMessage(`{
									"type":"object",
									"required":["id"],
									"properties":{"id":{"type":"string"}}
								}`),
								ParamLocations: map[string]string{"id": "path"},
							},
						},
					},
				},
			},
		},
	})

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "mcp-proxy-api-id",
			IsOAS: true,
		},
		OAS: *o,
	}
	return spec
}

func TestMCPHandlerMiddleware_Name(t *testing.T) {
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{}}
	if got := mw.Name(); got != "MCPHandler" {
		t.Errorf("Name: got %q want MCPHandler", got)
	}
}

func TestMCPHandlerMiddleware_EnabledForSpec(t *testing.T) {
	t.Run("enabled when MCPProxy extension present", func(t *testing.T) {
		spec := makeMCPHandlerSpec(t)
		mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
		if !mw.EnabledForSpec() {
			t.Errorf("expected enabled, got false")
		}
	})

	t.Run("disabled when no extension", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{IsOAS: true},
			OAS:           oas.OAS{},
		}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{})
		mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
		if mw.EnabledForSpec() {
			t.Errorf("expected disabled when MCPProxy absent")
		}
	})

	t.Run("disabled when not OAS", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: false}}
		mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
		if mw.EnabledForSpec() {
			t.Errorf("expected disabled for non-OAS spec")
		}
	})
}

// TestMCPHandlerMiddleware_Initialize covers the inline-response branch:
// an `initialize` envelope must produce a JSON-RPC result and short-
// circuit the chain (return middleware.StatusRespond).
func TestMCPHandlerMiddleware_Initialize(t *testing.T) {
	spec := makeMCPHandlerSpec(t)
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	err, code := mw.ProcessRequest(rec, req, nil)
	if err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}
	if code != middleware.StatusRespond {
		t.Errorf("code: got %d want StatusRespond(%d)", code, middleware.StatusRespond)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["protocolVersion"] != "2025-06-18" {
		t.Errorf("unexpected initialize response: %v", resp)
	}
}

// TestMCPHandlerMiddleware_NonPostPassthrough verifies that a GET (e.g.
// dashboard health probe) bypasses the middleware untouched.
func TestMCPHandlerMiddleware_NonPostPassthrough(t *testing.T) {
	spec := makeMCPHandlerSpec(t)
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	err, code := mw.ProcessRequest(rec, req, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code: got %d want %d", code, http.StatusOK)
	}
}

// captureMCPLog installs a logrus test hook on the gateway-package
// `log` logger, returning the hook plus a t.Cleanup-bound restore.
// We hook the underlying *logrus.Logger so log.WithFields(...).Info(...)
// entries are captured.
func captureMCPLog(t *testing.T) *logrustest.Hook {
	t.Helper()
	hook := logrustest.NewLocal(log)
	prevLevel := log.Level
	log.Level = logrus.DebugLevel
	t.Cleanup(func() {
		log.Level = prevLevel
		// logrustest hooks are append-only on the logger; remove them by
		// resetting the hook bucket to a clean state. Use a mutex here
		// to be safe if other tests run concurrently.
		var mu sync.Mutex
		mu.Lock()
		log.Hooks = make(logrus.LevelHooks)
		mu.Unlock()
	})
	return hook
}

// findMCPLogEntry returns the most recent logrus entry whose Message is
// "mcp.tool_call", or nil if none.
func findMCPLogEntry(hook *logrustest.Hook) *logrus.Entry {
	for i := len(hook.Entries) - 1; i >= 0; i-- {
		e := hook.Entries[i]
		if e.Message == "mcp.tool_call" {
			return &hook.Entries[i]
		}
	}
	return nil
}

// makeMCPHandlerSpecWithSources extends the basic fixture with both a
// loopback (with AcceptMCPLoopCallers=true) source and an upstream
// source carrying UpstreamCred. Used by the §14 log tests.
func makeMCPHandlerSpecWithSources(t *testing.T) *APISpec {
	t.Helper()
	o := &oas.OAS{}
	o.OpenAPI = "3.1.0"
	o.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			MCPProxy: &oas.MCPProxy{
				ProtocolVersion: "2025-06-18",
				Sources: []oas.MCPSource{
					{
						SourceSlug:  "hello-svc",
						BackendMode: "loopback",
						SourceAPIID: "hello-api-id",
						Tools: []oas.MCPToolMapping{
							{
								ToolName:     "hello-svc__get_hello",
								Method:       "GET",
								PathTemplate: "/hello/{id}",
								InputSchema: json.RawMessage(`{
									"type":"object",
									"required":["id"],
									"properties":{"id":{"type":"string"}}
								}`),
								ParamLocations: map[string]string{"id": "path"},
							},
						},
					},
					{
						SourceSlug:  "users-svc",
						BackendMode: "upstream",
						UpstreamURL: "https://upstream.example.com",
						UpstreamCred: &oas.UpstreamCred{
							AuthType:    "bearer",
							SecretValue: "tok",
						},
						Tools: []oas.MCPToolMapping{
							{
								ToolName:     "users-svc__get_users_id",
								Method:       "GET",
								PathTemplate: "/users/{id}",
								InputSchema: json.RawMessage(`{
									"type":"object",
									"required":["id"],
									"properties":{"id":{"type":"string"}}
								}`),
								ParamLocations: map[string]string{"id": "path"},
							},
						},
					},
				},
			},
		},
	})

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "mcp-proxy-api-id",
			IsOAS: true,
		},
		OAS: *o,
	}
	return spec
}

// makeSourceSpec builds a minimal APISpec carrying an OAS extension with
// the given AcceptMCPLoopCallers / UseKeylessAccess settings. Used to
// populate gw.apisByID so deriveAuthPath can resolve the source.
func makeSourceSpec(apiID string, accept bool, keyless bool) *APISpec {
	o := oas.OAS{}
	o.OpenAPI = "3.1.0"
	o.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			AcceptMCPLoopCallers: accept,
		},
	})
	return &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:            apiID,
			IsOAS:            true,
			UseKeylessAccess: keyless,
		},
		OAS: o,
	}
}

// TestMCPHandlerMiddleware_ToolCallLog_Loopback verifies the §14
// structured log line is emitted with auth_path=mcp_caller_auth on a
// successful tools/call hand-off to a loopback source whose APIDef has
// AcceptMCPLoopCallers=true.
func TestMCPHandlerMiddleware_ToolCallLog_Loopback(t *testing.T) {
	spec := makeMCPHandlerSpecWithSources(t)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"hello-api-id": makeSourceSpec("hello-api-id", true, true),
		},
	}
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	hook := captureMCPLog(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":"alice"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tyk-Agent-Id", "agent-42")
	rec := httptest.NewRecorder()

	if err, _ := mw.ProcessRequest(rec, req, nil); err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}

	entry := findMCPLogEntry(hook)
	if entry == nil {
		t.Fatalf("expected mcp.tool_call log entry, got %d entries", len(hook.Entries))
	}
	want := map[string]interface{}{
		"proxy_apiid": "mcp-proxy-api-id",
		"source_slug": "hello-svc",
		"tool_name":   "hello-svc__get_hello",
		"mode":        "loopback",
		"agent_id":    "agent-42",
		"auth_path":   "mcp_caller_auth",
		"outcome":     "success",
	}
	for k, v := range want {
		if got := entry.Data[k]; got != v {
			t.Errorf("field %q: got %v, want %v", k, got, v)
		}
	}
	if _, ok := entry.Data["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing or wrong type: %T", entry.Data["duration_ms"])
	}
}

// TestMCPHandlerMiddleware_ToolCallLog_Upstream verifies auth_path is
// `upstream_cred` for an upstream-mode source carrying UpstreamCred.
func TestMCPHandlerMiddleware_ToolCallLog_Upstream(t *testing.T) {
	spec := makeMCPHandlerSpecWithSources(t)
	// Upstream mode does not need apisByID lookup; use empty gateway.
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	hook := captureMCPLog(t)

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"users-svc__get_users_id","arguments":{"id":"u_123"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	if err, _ := mw.ProcessRequest(rec, req, nil); err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}

	entry := findMCPLogEntry(hook)
	if entry == nil {
		t.Fatalf("expected mcp.tool_call log entry, got %d entries", len(hook.Entries))
	}
	if entry.Data["mode"] != "upstream" {
		t.Errorf("mode: got %v, want upstream", entry.Data["mode"])
	}
	if entry.Data["auth_path"] != "upstream_cred" {
		t.Errorf("auth_path: got %v, want upstream_cred", entry.Data["auth_path"])
	}
	if entry.Data["outcome"] != "success" {
		t.Errorf("outcome: got %v, want success", entry.Data["outcome"])
	}
	if entry.Data["source_slug"] != "users-svc" {
		t.Errorf("source_slug: got %v, want users-svc", entry.Data["source_slug"])
	}
}

// TestMCPHandlerMiddleware_ToolCallLog_UnknownTool verifies that an
// inline JSON-RPC error (tool not found) emits the log with
// outcome=json_rpc_error.
func TestMCPHandlerMiddleware_ToolCallLog_UnknownTool(t *testing.T) {
	spec := makeMCPHandlerSpecWithSources(t)
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	hook := captureMCPLog(t)

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"does-not-exist","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	if err, _ := mw.ProcessRequest(rec, req, nil); err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}

	entry := findMCPLogEntry(hook)
	if entry == nil {
		t.Fatalf("expected mcp.tool_call log entry, got %d entries", len(hook.Entries))
	}
	if entry.Data["outcome"] != "json_rpc_error" {
		t.Errorf("outcome: got %v, want json_rpc_error", entry.Data["outcome"])
	}
	if entry.Data["tool_name"] != "does-not-exist" {
		t.Errorf("tool_name: got %v, want does-not-exist", entry.Data["tool_name"])
	}
	// Source lookup miss; mode falls back to default (loopback) and
	// auth_path to unknown.
	if entry.Data["auth_path"] != "unknown" {
		t.Errorf("auth_path: got %v, want unknown", entry.Data["auth_path"])
	}
}

// TestMCPHandlerMiddleware_ToolCallLog_KeylessLoopback verifies a
// loopback source whose APIDef is keyless AND has
// AcceptMCPLoopCallers=false maps to auth_path=keyless_loopback.
func TestMCPHandlerMiddleware_ToolCallLog_KeylessLoopback(t *testing.T) {
	spec := makeMCPHandlerSpecWithSources(t)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"hello-api-id": makeSourceSpec("hello-api-id", false, true),
		},
	}
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	hook := captureMCPLog(t)

	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":"x"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	if err, _ := mw.ProcessRequest(rec, req, nil); err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}

	entry := findMCPLogEntry(hook)
	if entry == nil {
		t.Fatalf("expected mcp.tool_call log entry")
	}
	if entry.Data["auth_path"] != "keyless_loopback" {
		t.Errorf("auth_path: got %v, want keyless_loopback", entry.Data["auth_path"])
	}
}

// TestMCPHandlerMiddleware_ToolCallLog_NotEmittedForInitialize verifies
// that non-tools/call methods do NOT emit the §14 log line.
func TestMCPHandlerMiddleware_ToolCallLog_NotEmittedForInitialize(t *testing.T) {
	spec := makeMCPHandlerSpecWithSources(t)
	gw := &Gateway{apisByID: map[string]*APISpec{}}
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec, Gw: gw}}
	hook := captureMCPLog(t)

	body := `{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	if err, _ := mw.ProcessRequest(rec, req, nil); err != nil {
		t.Fatalf("ProcessRequest err: %v", err)
	}
	if entry := findMCPLogEntry(hook); entry != nil {
		t.Errorf("did not expect mcp.tool_call log for initialize; got %v", entry.Data)
	}
}

// TestMCPHandlerMiddleware_ToolsCallSetsRewrite verifies the gateway
// shell wires ctxSetURLRewriteTarget through to the proxy package.
func TestMCPHandlerMiddleware_ToolsCallSetsRewrite(t *testing.T) {
	spec := makeMCPHandlerSpec(t)
	mw := &MCPHandlerMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":"alice"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer agent-bearer")
	rec := httptest.NewRecorder()

	err, code := mw.ProcessRequest(rec, req, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("code: got %d want StatusOK (proxy hand-off)", code)
	}
	target := ctxGetURLRewriteTarget(req)
	if target == nil {
		t.Fatalf("URL rewrite target not set")
	}
	if target.Scheme != "tyk" || target.Host != "hello-api-id" || target.Path != "/hello/alice" {
		t.Errorf("rewrite target: got %v want tyk://hello-api-id/hello/alice", target)
	}
	// Authorization header must have been stripped.
	if req.Header.Get("Authorization") != "" {
		t.Errorf("Authorization not stripped")
	}
}
