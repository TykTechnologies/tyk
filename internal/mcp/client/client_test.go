package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rpcHandler is a helper that routes JSON-RPC methods to handler funcs.
type rpcHandler struct {
	sessionID string
	handlers  map[string]func(id *int64, params json.RawMessage) (any, *jsonRPCError)
	calls     []string
}

func (h *rpcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.calls = append(h.calls, req.Method)

	// Set session header on initialize response.
	if req.Method == "initialize" && h.sessionID != "" {
		w.Header().Set(sessionHeader, h.sessionID)
	}

	// Notifications have no ID and expect no response body.
	if req.ID == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	fn, ok := h.handlers[req.Method]
	if !ok {
		writeRPCError(w, req.ID, -32601, "method not found")
		return
	}

	raw, _ := json.Marshal(req.Params)
	result, rpcErr := fn(req.ID, raw)

	if rpcErr != nil {
		writeRPCError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	resultJSON, _ := json.Marshal(result)
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resultJSON,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeRPCError(w http.ResponseWriter, id *int64, code int, msg string) {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: msg},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func initializeHandler() func(*int64, json.RawMessage) (any, *jsonRPCError) {
	return func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"serverInfo": map[string]any{
				"name":    "test-server",
				"version": "0.1.0",
			},
		}, nil
	}
}

func TestIntrospect_Success(t *testing.T) {
	h := &rpcHandler{
		sessionID: "sess-123",
		handlers: map[string]func(*int64, json.RawMessage) (any, *jsonRPCError){
			"initialize": initializeHandler(),
			"tools/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"tools": []map[string]any{
						{"name": "get_weather", "description": "Get weather for a location"},
						{"name": "search", "description": "Search the web"},
					},
				}, nil
			},
			"resources/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"resources": []map[string]any{
						{"uri": "file:///data.csv", "name": "data", "mimeType": "text/csv"},
					},
				}, nil
			},
			"prompts/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"prompts": []map[string]any{
						{
							"name":        "summarize",
							"description": "Summarize text",
							"arguments": []map[string]any{
								{"name": "text", "required": true},
							},
						},
					},
				}, nil
			},
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	result, err := c.Introspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Partial {
		t.Errorf("expected non-partial result, got partial with errors: %v", result.Errors)
	}

	caps := result.Capabilities
	if caps.ServerInfo.Name != "test-server" || caps.ServerInfo.Version != "0.1.0" {
		t.Errorf("unexpected server info: %+v", caps.ServerInfo)
	}

	if len(caps.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(caps.Tools))
	}
	if caps.Tools[0].Name != "get_weather" {
		t.Errorf("expected tool name 'get_weather', got %q", caps.Tools[0].Name)
	}

	if len(caps.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(caps.Resources))
	}
	if caps.Resources[0].URI != "file:///data.csv" {
		t.Errorf("unexpected resource URI: %s", caps.Resources[0].URI)
	}

	if len(caps.Prompts) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(caps.Prompts))
	}
	if caps.Prompts[0].Name != "summarize" {
		t.Errorf("expected prompt name 'summarize', got %q", caps.Prompts[0].Name)
	}
	if len(caps.Prompts[0].Arguments) != 1 || !caps.Prompts[0].Arguments[0].Required {
		t.Errorf("unexpected prompt arguments: %+v", caps.Prompts[0].Arguments)
	}

	// Verify the call sequence.
	expected := []string{"initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list"}
	if len(h.calls) != len(expected) {
		t.Fatalf("expected %d calls, got %d: %v", len(expected), len(h.calls), h.calls)
	}
	for i, m := range expected {
		if h.calls[i] != m {
			t.Errorf("call %d: expected %q, got %q", i, m, h.calls[i])
		}
	}
}

func TestIntrospect_Pagination(t *testing.T) {
	var toolsPage atomic.Int32

	h := &rpcHandler{
		sessionID: "sess-page",
		handlers: map[string]func(*int64, json.RawMessage) (any, *jsonRPCError){
			"initialize": initializeHandler(),
			"tools/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				page := toolsPage.Add(1)
				var p struct {
					Cursor string `json:"cursor"`
				}
				json.Unmarshal(params, &p)

				switch page {
				case 1:
					if p.Cursor != "" {
						return nil, &jsonRPCError{Code: -1, Message: "unexpected cursor on first page"}
					}
					return map[string]any{
						"tools": []map[string]any{
							{"name": "tool_a"},
							{"name": "tool_b"},
						},
						"nextCursor": "page2",
					}, nil
				case 2:
					if p.Cursor != "page2" {
						return nil, &jsonRPCError{Code: -1, Message: fmt.Sprintf("expected cursor 'page2', got %q", p.Cursor)}
					}
					return map[string]any{
						"tools": []map[string]any{
							{"name": "tool_c"},
						},
					}, nil
				default:
					return nil, &jsonRPCError{Code: -1, Message: "too many pages"}
				}
			},
			"resources/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{"resources": []any{}}, nil
			},
			"prompts/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{"prompts": []any{}}, nil
			},
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	result, err := c.Introspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Partial {
		t.Errorf("expected non-partial result, errors: %v", result.Errors)
	}
	if len(result.Capabilities.Tools) != 3 {
		t.Fatalf("expected 3 tools across pages, got %d", len(result.Capabilities.Tools))
	}

	names := make([]string, len(result.Capabilities.Tools))
	for i, tool := range result.Capabilities.Tools {
		names[i] = tool.Name
	}
	want := "tool_a,tool_b,tool_c"
	got := strings.Join(names, ",")
	if got != want {
		t.Errorf("expected tools %q, got %q", want, got)
	}
}

func TestIntrospect_SSEResponse(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonRPCRequest
		json.NewDecoder(r.Body).Decode(&req)
		callCount++

		if req.ID == nil {
			// Notification.
			w.WriteHeader(http.StatusOK)
			return
		}

		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set(sessionHeader, "sse-sess")
			result = map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "sse-server", "version": "0.2.0"},
			}
		case "tools/list":
			result = map[string]any{
				"tools": []map[string]any{
					{"name": "sse_tool", "description": "A tool from SSE"},
				},
			}
		case "resources/list":
			result = map[string]any{"resources": []any{}}
		case "prompts/list":
			result = map[string]any{"prompts": []any{}}
		}

		resultJSON, _ := json.Marshal(result)
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  resultJSON,
		}
		respJSON, _ := json.Marshal(resp)

		// Respond as SSE.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(respJSON))
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	result, err := c.Introspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Capabilities.ServerInfo.Name != "sse-server" {
		t.Errorf("expected sse-server, got %q", result.Capabilities.ServerInfo.Name)
	}
	if len(result.Capabilities.Tools) != 1 || result.Capabilities.Tools[0].Name != "sse_tool" {
		t.Errorf("unexpected tools: %+v", result.Capabilities.Tools)
	}
}

func TestIntrospect_UpstreamDown(t *testing.T) {
	// Use a server that is immediately closed to simulate connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c := New()
	_, err := c.Introspect(ctx, url)
	if err == nil {
		t.Fatal("expected error for closed server, got nil")
	}
	if !strings.Contains(err.Error(), "mcp initialize") {
		t.Errorf("expected error to mention initialize, got: %v", err)
	}
}

func TestIntrospect_PartialFailure(t *testing.T) {
	h := &rpcHandler{
		sessionID: "sess-partial",
		handlers: map[string]func(*int64, json.RawMessage) (any, *jsonRPCError){
			"initialize": initializeHandler(),
			"tools/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"tools": []map[string]any{
						{"name": "working_tool"},
					},
				}, nil
			},
			"resources/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return nil, &jsonRPCError{Code: -32603, Message: "internal error"}
			},
			"prompts/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"prompts": []map[string]any{
						{"name": "working_prompt"},
					},
				}, nil
			},
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	result, err := c.Introspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Partial {
		t.Error("expected partial result")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Method != "resources/list" {
		t.Errorf("expected error for resources/list, got %q", result.Errors[0].Method)
	}

	// Tools and prompts should still be populated.
	if len(result.Capabilities.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(result.Capabilities.Tools))
	}
	if len(result.Capabilities.Prompts) != 1 {
		t.Errorf("expected 1 prompt, got %d", len(result.Capabilities.Prompts))
	}
	// Resources should be nil since the list failed.
	if result.Capabilities.Resources != nil {
		t.Errorf("expected nil resources, got %+v", result.Capabilities.Resources)
	}
}

func TestIntrospect_InvalidPrimitiveName(t *testing.T) {
	h := &rpcHandler{
		sessionID: "sess-invalid",
		handlers: map[string]func(*int64, json.RawMessage) (any, *jsonRPCError){
			"initialize": initializeHandler(),
			"tools/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{
					"tools": []map[string]any{
						{"name": "valid_tool"},
						{"name": "invalid tool with spaces"},
						{"name": "also-valid.tool/v1"},
						{"name": ""},
						{"name": strings.Repeat("a", 257)},
						{"name": "has$pecial"},
					},
				}, nil
			},
			"resources/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{"resources": []any{}}, nil
			},
			"prompts/list": func(id *int64, params json.RawMessage) (any, *jsonRPCError) {
				return map[string]any{"prompts": []any{}}, nil
			},
		},
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	result, err := c.Introspect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only "valid_tool" and "also-valid.tool/v1" should pass validation.
	if len(result.Capabilities.Tools) != 2 {
		t.Fatalf("expected 2 valid tools, got %d: %+v", len(result.Capabilities.Tools), result.Capabilities.Tools)
	}

	names := make(map[string]bool)
	for _, tool := range result.Capabilities.Tools {
		names[tool.Name] = true
	}
	if !names["valid_tool"] {
		t.Error("expected valid_tool to be present")
	}
	if !names["also-valid.tool/v1"] {
		t.Error("expected also-valid.tool/v1 to be present")
	}
}

func TestExtractSSEData(t *testing.T) {
	t.Run("event message with data returns data", func(t *testing.T) {
		stream := "event: message\ndata: {\"hello\":\"world\"}\n\n"
		got, err := extractSSEData(strings.NewReader(stream))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != `{"hello":"world"}` {
			t.Errorf("got %q, want %q", string(got), `{"hello":"world"}`)
		}
	})

	t.Run("stream without trailing blank line still returns data", func(t *testing.T) {
		stream := "event: message\ndata: {\"key\":\"val\"}"
		got, err := extractSSEData(strings.NewReader(stream))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != `{"key":"val"}` {
			t.Errorf("got %q, want %q", string(got), `{"key":"val"}`)
		}
	})

	t.Run("empty stream returns error", func(t *testing.T) {
		_, err := extractSSEData(strings.NewReader(""))
		if err == nil {
			t.Fatal("expected error for empty stream")
		}
		if !strings.Contains(err.Error(), "no message event found") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("stream with only comments returns error", func(t *testing.T) {
		stream := ":this is a comment\n:another comment\n\n"
		_, err := extractSSEData(strings.NewReader(stream))
		if err == nil {
			t.Fatal("expected error for comment-only stream")
		}
		if !strings.Contains(err.Error(), "no message event found") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("non-message event followed by message event returns message data", func(t *testing.T) {
		stream := "event: status\ndata: ignored\n\nevent: message\ndata: {\"result\":true}\n\n"
		got, err := extractSSEData(strings.NewReader(stream))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != `{"result":true}` {
			t.Errorf("got %q, want %q", string(got), `{"result":true}`)
		}
	})
}

func TestDoRPC_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()))
	id := int64(1)
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "test",
	}

	_, _, err := c.doRPC(context.Background(), srv.URL, "", req)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("expected error to contain 'unexpected status 500', got: %v", err)
	}
}

func TestParseTools_MalformedJSON(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"name":"valid_tool","description":"a tool"}`),
		json.RawMessage(`not json`),
		json.RawMessage(`{"name":"another_valid","description":"another"}`),
	}

	tools := parseTools(raw)
	if len(tools) != 2 {
		t.Fatalf("expected 2 valid tools, got %d", len(tools))
	}
	if tools[0].Name != "valid_tool" {
		t.Errorf("expected first tool 'valid_tool', got %q", tools[0].Name)
	}
	if tools[1].Name != "another_valid" {
		t.Errorf("expected second tool 'another_valid', got %q", tools[1].Name)
	}
}

func TestParseResources_MalformedJSON(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"uri":"file:///data","name":"data"}`),
		json.RawMessage(`not json`),
		json.RawMessage(`{"uri":"file:///config","name":"config"}`),
	}

	resources := parseResources(raw)
	if len(resources) != 2 {
		t.Fatalf("expected 2 valid resources, got %d", len(resources))
	}
	if resources[0].Name != "data" {
		t.Errorf("expected first resource 'data', got %q", resources[0].Name)
	}
	if resources[1].Name != "config" {
		t.Errorf("expected second resource 'config', got %q", resources[1].Name)
	}
}

func TestParsePrompts_MalformedJSON(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"name":"summarize","description":"summarize text"}`),
		json.RawMessage(`not json`),
		json.RawMessage(`{"name":"translate","description":"translate text"}`),
	}

	prompts := parsePrompts(raw)
	if len(prompts) != 2 {
		t.Fatalf("expected 2 valid prompts, got %d", len(prompts))
	}
	if prompts[0].Name != "summarize" {
		t.Errorf("expected first prompt 'summarize', got %q", prompts[0].Name)
	}
	if prompts[1].Name != "translate" {
		t.Errorf("expected second prompt 'translate', got %q", prompts[1].Name)
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"simple", true},
		{"with-dash", true},
		{"with_underscore", true},
		{"with.dot", true},
		{"with/slash", true},
		{"with:colon", true},
		{"with*star", true},
		{"with@at", true},
		{"combo_tool-v1.0/api:get", true},
		{"", false},
		{"has space", false},
		{"has$dollar", false},
		{"has!bang", false},
		{strings.Repeat("x", 256), true},
		{strings.Repeat("x", 257), false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.name), func(t *testing.T) {
			got := validateName(tt.name)
			if got != tt.valid {
				t.Errorf("validateName(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}
