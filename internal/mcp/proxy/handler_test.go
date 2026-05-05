package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oas "github.com/TykTechnologies/tyk/apidef/oas"
)

// fixture builds a two-source MCPProxy used across the table:
// - "hello-svc" loopback with a single tool "hello-svc__get_hello"
//   (GET /hello/{id}?lang=...&X-Trace-Id: header, no body)
// - "weather" upstream with a single tool "weather__post_forecast"
//   (POST /forecast with body args, plus a Disabled tool)
func fixture() *oas.MCPProxy {
	helloSchema := json.RawMessage(`{
		"type":"object",
		"required":["id"],
		"properties":{
			"id":{"type":"string"},
			"lang":{"type":"string"},
			"X-Trace-Id":{"type":"string"}
		}
	}`)
	forecastSchema := json.RawMessage(`{
		"type":"object",
		"required":["lat","lon"],
		"properties":{
			"lat":{"type":"number"},
			"lon":{"type":"number"}
		}
	}`)
	disabledSchema := json.RawMessage(`{"type":"object"}`)

	return &oas.MCPProxy{
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
						InputSchema:  helloSchema,
						ParamLocations: map[string]string{
							"id":         "path",
							"lang":       "query",
							"X-Trace-Id": "header",
						},
					},
				},
			},
			{
				SourceSlug:  "weather",
				BackendMode: "upstream",
				UpstreamURL: "https://upstream.example.com/api",
				UpstreamCred: &oas.UpstreamCred{
					AuthType:    "header",
					HeaderName:  "X-API-Key",
					SecretValue: "s3cret",
				},
				Tools: []oas.MCPToolMapping{
					{
						ToolName:       "weather__post_forecast",
						Method:         "POST",
						PathTemplate:   "/forecast",
						InputSchema:    forecastSchema,
						ParamLocations: map[string]string{
							// lat/lon have no entry → body-bound
						},
					},
					{
						ToolName:     "weather__disabled",
						Method:       "GET",
						PathTemplate: "/x",
						InputSchema:  disabledSchema,
						Disabled:     true,
					},
				},
			},
		},
	}
}

// newTestHandler builds a Handler whose URLRewriteSetter records the
// last target URL into the supplied pointer.
func newTestHandler(t *testing.T, captured **url.URL) *Handler {
	t.Helper()
	return NewHandler(
		fixture(),
		DefaultValidator(),
		WithProxyAPIID("proxy-api-id"),
		WithURLRewriteSetter(func(r *http.Request, u *url.URL) *http.Request {
			*captured = u
			return r
		}),
	)
}

// dispatchEnvelope is a small helper that invokes Dispatch with the
// given JSON-RPC body and returns (action, response-recorder, request).
func dispatchEnvelope(t *testing.T, h *Handler, body string) (Action, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer agent-bearer")
	rec := httptest.NewRecorder()
	action, err := h.Dispatch(rec, req)
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	return action, rec, req
}

func decodeJSONRPC(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	return m
}

// ---- initialize ---------------------------------------------------------

func TestDispatch_Initialize(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	action, rec, _ := dispatchEnvelope(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result in %v", resp)
	}
	if result["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion: got %v want 2025-06-18", result["protocolVersion"])
	}
	caps, _ := result["capabilities"].(map[string]any)
	if caps == nil {
		t.Fatalf("missing capabilities")
	}
	tools, _ := caps["tools"].(map[string]any)
	if tools == nil || tools["listChanged"] != false {
		t.Errorf("tools.listChanged: got %v want false", tools)
	}
}

// ---- tools/list ---------------------------------------------------------

func TestDispatch_ToolsList_FiltersDisabled(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	action, rec, _ := dispatchEnvelope(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	result, _ := resp["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	names := make([]string, 0, len(tools))
	for _, ti := range tools {
		tm, _ := ti.(map[string]any)
		if n, ok := tm["name"].(string); ok {
			names = append(names, n)
		}
	}
	wantContains := []string{"hello-svc__get_hello", "weather__post_forecast"}
	for _, w := range wantContains {
		found := false
		for _, n := range names {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tools/list missing %q (got %v)", w, names)
		}
	}
	for _, n := range names {
		if n == "weather__disabled" {
			t.Errorf("tools/list should have filtered disabled tool, got %v", names)
		}
	}
}

// ---- tools/call: unknown name ------------------------------------------

func TestDispatch_ToolsCall_UnknownName(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	action, rec, _ := dispatchEnvelope(t, h,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"does-not-exist","arguments":{}}}`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32601 {
		t.Errorf("error code: got %v want -32601", code)
	}
}

// ---- tools/call: schema mismatch ---------------------------------------

func TestDispatch_ToolsCall_InvalidArgs(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	// "id" is required (string) — pass int instead.
	action, rec, _ := dispatchEnvelope(t, h,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":42}}}`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32602 {
		t.Errorf("error code: got %v want -32602", code)
	}
}

// ---- tools/call: loopback success --------------------------------------

func TestDispatch_ToolsCall_LoopbackSuccess(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":"alice","lang":"en","X-Trace-Id":"abc-123"}}}`
	action, _, req := dispatchEnvelope(t, h, body)

	if action != ActionProxy {
		t.Fatalf("action: got %v want ActionProxy", action)
	}
	if req.Method != http.MethodGet {
		t.Errorf("req.Method: got %s want GET", req.Method)
	}
	if req.URL.Path != "/hello/alice" {
		t.Errorf("req.URL.Path: got %q want /hello/alice", req.URL.Path)
	}
	if got := req.URL.Query().Get("lang"); got != "en" {
		t.Errorf("query.lang: got %q want en", got)
	}
	if got := req.Header.Get("X-Trace-Id"); got != "abc-123" {
		t.Errorf("header X-Trace-Id: got %q want abc-123", got)
	}
	// Authorization stripped.
	if req.Header.Get("Authorization") != "" {
		t.Errorf("Authorization not stripped: %q", req.Header.Get("Authorization"))
	}
	// X-Tyk-MCP-Context injected (loopback only).
	ctxHdr := req.Header.Get("X-Tyk-MCP-Context")
	if ctxHdr == "" {
		t.Fatalf("X-Tyk-MCP-Context not set on loopback")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(ctxHdr), &parsed); err != nil {
		t.Fatalf("X-Tyk-MCP-Context not valid JSON: %v", err)
	}
	if parsed["proxy_apiid"] != "proxy-api-id" {
		t.Errorf("X-Tyk-MCP-Context.proxy_apiid: got %v", parsed["proxy_apiid"])
	}
	if parsed["tool_name"] != "hello-svc__get_hello" {
		t.Errorf("X-Tyk-MCP-Context.tool_name: got %v", parsed["tool_name"])
	}
	// URL-rewrite target.
	if captured == nil {
		t.Fatalf("urlRewrite not invoked")
	}
	if captured.Scheme != "tyk" || captured.Host != "hello-api-id" || captured.Path != "/hello/alice" {
		t.Errorf("rewrite target: got %v want tyk://hello-api-id/hello/alice", captured)
	}
	// Stashed id and tool name accessible from context.
	if id, ok := GetJSONRPCID(req); !ok {
		t.Errorf("JSONRPCID not stashed")
	} else if f, _ := id.(float64); f != 5 {
		t.Errorf("JSONRPCID: got %v want 5", id)
	}
	if name, ok := GetToolName(req); !ok || name != "hello-svc__get_hello" {
		t.Errorf("ToolName: got %q ok=%v", name, ok)
	}
}

// ---- tools/call: upstream success --------------------------------------

func TestDispatch_ToolsCall_UpstreamSuccess(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	body := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"weather__post_forecast","arguments":{"lat":52.5,"lon":13.4}}}`
	action, _, req := dispatchEnvelope(t, h, body)

	if action != ActionProxy {
		t.Fatalf("action: got %v want ActionProxy", action)
	}
	if req.Method != http.MethodPost {
		t.Errorf("req.Method: got %s want POST", req.Method)
	}
	// X-Tyk-MCP-Context must NOT be injected on upstream mode.
	if req.Header.Get("X-Tyk-MCP-Context") != "" {
		t.Errorf("X-Tyk-MCP-Context leaked to upstream: %q", req.Header.Get("X-Tyk-MCP-Context"))
	}
	// UpstreamCred header applied.
	if got := req.Header.Get("X-API-Key"); got != "s3cret" {
		t.Errorf("X-API-Key: got %q want s3cret", got)
	}
	// URL-rewrite target points at the upstream.
	if captured == nil {
		t.Fatalf("urlRewrite not invoked")
	}
	if captured.Scheme != "https" || captured.Host != "upstream.example.com" {
		t.Errorf("rewrite scheme/host: got %s://%s want https://upstream.example.com", captured.Scheme, captured.Host)
	}
	if captured.Path != "/api/forecast" {
		t.Errorf("rewrite path: got %q want /api/forecast", captured.Path)
	}
	// Body is JSON-encoded.
	bodyBytes, _ := io.ReadAll(req.Body)
	var got map[string]any
	if err := json.Unmarshal(bodyBytes, &got); err != nil {
		t.Fatalf("body not JSON: %v body=%s", err, bodyBytes)
	}
	if got["lat"] != 52.5 || got["lon"] != 13.4 {
		t.Errorf("body: got %v want lat=52.5 lon=13.4", got)
	}
}

// ---- tools/call: header CRLF injection ---------------------------------

func TestDispatch_ToolsCall_HeaderCRLFRejected(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	// X-Trace-Id is a string per schema — schema accepts; CRLF check must
	// reject AFTER schema validation per RFC §8.3 step 3.
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hello-svc__get_hello","arguments":{"id":"alice","X-Trace-Id":"abc\r\nX-Injected: 1"}}}`
	action, rec, _ := dispatchEnvelope(t, h, body)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32602 {
		t.Errorf("error code: got %v want -32602", code)
	}
}

// ---- tools/call: TE/CL hygiene -----------------------------------------

func TestDispatch_ToolsCall_TransferEncodingCleared(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)

	body := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"weather__post_forecast","arguments":{"lat":1.0,"lon":2.0}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer agent")
	// Pre-existing TE header that must be wiped after substitution.
	req.Header.Set("Transfer-Encoding", "chunked")
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	action, err := h.Dispatch(rec, req)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if action != ActionProxy {
		t.Fatalf("action: got %v want ActionProxy", action)
	}
	if req.Header.Get("Transfer-Encoding") != "" {
		t.Errorf("Transfer-Encoding not cleared: %v", req.Header.Get("Transfer-Encoding"))
	}
	if len(req.TransferEncoding) != 0 {
		t.Errorf("req.TransferEncoding not cleared: %v", req.TransferEncoding)
	}
	// Content-Length matches the actual body bytes we wrote.
	bodyBytes, _ := io.ReadAll(req.Body)
	cl := req.Header.Get("Content-Length")
	if cl == "" {
		t.Fatalf("Content-Length not set")
	}
	if got := int64(len(bodyBytes)); req.ContentLength != got {
		t.Errorf("ContentLength: header=%s field=%d body-bytes=%d", cl, req.ContentLength, got)
	}
	// Reset body for any downstream readers in the same test (defensive).
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
}

// ---- envelope parse ----------------------------------------------------

// TestDispatch_EnvelopeParseError covers RFC §15.1's "JSON-RPC envelope
// parse" bullet: a malformed body must surface as a JSON-RPC error
// envelope (code -32700) rather than a transport-level error.
func TestDispatch_EnvelopeParseError(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	// Truncated JSON — not a valid JSON-RPC envelope.
	action, rec, _ := dispatchEnvelope(t, h, `{"jsonrpc":"2.0","id":1,"method":`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32700 {
		t.Errorf("error code: got %v want -32700", int(code))
	}
}

// ---- internal error (-32603) -------------------------------------------

// TestDispatch_ToolsCall_InternalError_SchemaCompile covers RFC §15.1's
// "-32603" mapping bullet. The handler maps schema-compile failures (and
// other internal-only faults — marshal arguments, build target, encode
// body) to JSON-RPC InternalError. We exercise the schema-compile path by
// installing a fixture whose InputSchema is structurally invalid JSON
// (per-resource registration fails inside Validator.Compile).
func TestDispatch_ToolsCall_InternalError_SchemaCompile(t *testing.T) {
	// Hand-built fixture: same shape as fixture() but with a deliberately
	// invalid InputSchema so DefaultValidator().Compile returns an error.
	p := &oas.MCPProxy{
		ProtocolVersion: "2025-06-18",
		Sources: []oas.MCPSource{
			{
				SourceSlug:  "broken",
				BackendMode: "loopback",
				SourceAPIID: "broken-api-id",
				Tools: []oas.MCPToolMapping{
					{
						ToolName:     "broken__tool",
						Method:       "GET",
						PathTemplate: "/x",
						// Not valid JSON at all -> Compile returns error.
						InputSchema: json.RawMessage(`not-json`),
					},
				},
			},
		},
	}
	var captured *url.URL
	h := NewHandler(
		p,
		DefaultValidator(),
		WithProxyAPIID("proxy-api-id"),
		WithURLRewriteSetter(func(r *http.Request, u *url.URL) *http.Request {
			captured = u
			return r
		}),
	)

	body := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"broken__tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	action, err := h.Dispatch(rec, req)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32603 {
		t.Errorf("error code: got %v want -32603", int(code))
	}
	// urlRewrite must NOT have fired — we errored before step 7.
	if captured != nil {
		t.Errorf("urlRewrite invoked despite internal error: %v", captured)
	}
}

// ---- unknown method ----------------------------------------------------

func TestDispatch_UnknownMethod(t *testing.T) {
	var captured *url.URL
	h := newTestHandler(t, &captured)
	action, rec, _ := dispatchEnvelope(t, h, `{"jsonrpc":"2.0","id":9,"method":"frobnicate","params":{}}`)

	if action != ActionRespond {
		t.Fatalf("action: got %v want ActionRespond", action)
	}
	resp := decodeJSONRPC(t, rec.Body.Bytes())
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error, got %v", resp)
	}
	code, _ := errObj["code"].(float64)
	if int(code) != -32601 {
		t.Errorf("error code: got %v want -32601", code)
	}
}
