// Package adapter contains the pure (gateway-agnostic) building blocks
// of the REST-as-MCP adapter: JSON-RPC envelope shapes, tool-argument
// expansion into an http.Request, and the size-capped response
// recorder used to wrap the looped REST response as an MCP
// `result.content[]` envelope.
//
// The package is consumed by the gateway's loader/synthesiser and the
// SDK-backed synthetic adapter. Splitting it out keeps the gateway package
// free of MCP protocol details and makes the protocol-level logic
// independently testable.
package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// BodyTruncationBytes is the maximum size of an upstream response body
// the adapter inlines into the MCP `result.content[]` envelope. Bodies
// larger than this are truncated and the envelope is tagged
// `_meta.truncated: true`.
const BodyTruncationBytes = 1 << 20 // 1 MiB

// Method names the adapter answers inline. The mcp package does not
// declare these as constants; they are spec-level identifiers.
const (
	MethodInitialize = "initialize"
	MethodPing       = "ping"
)

// ProtocolVersion is the MCP protocol version this adapter advertises
// in its `initialize` result.
const ProtocolVersion = "2025-06-18"

// JSON-RPC error codes referenced by the adapter. (Duplicated from
// internal/mcp/jsonrpc.go to avoid an import cycle: the gateway-level
// JSONRPC middleware also depends on this package.)
const (
	JSONRPCMethodNotFound = -32601
	JSONRPCInvalidParams  = -32602
	JSONRPCInternalError  = -32603
)

// Request is the slimmed-down JSON-RPC request shape the adapter
// reads. Mirrors the field set the gateway-side JSONRPCMiddleware
// already parses.
type Request struct {
	ID     any             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// HandlerResolver returns the in-process handler for an APIID. The
// gateway implements this against its apisHandlesByID; tests pass a
// fake that returns a recording handler.
type HandlerResolver interface {
	Handler(apiID string) (http.Handler, bool)
}

// FindTool returns the DerivedTool with the given name or nil.
func FindTool(tools []oas.DerivedTool, name string) *oas.DerivedTool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

// InitializeResult builds the JSON object served as the `result` of
// `initialize`. serverName is typically the adapter's APISpec Name.
func InitializeResult(serverName string) map[string]any {
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"serverInfo": map[string]any{
			"name":    serverName,
			"version": "1.0",
		},
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
	}
}

// ToolsListResult builds the `result` for `tools/list` from the
// derived catalogue.
func ToolsListResult(tools []oas.DerivedTool) map[string]any {
	items := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		entry := map[string]any{
			"name":        t.Name,
			"inputSchema": t.InputSchema,
		}
		if t.Description != "" {
			entry["description"] = t.Description
		}
		items = append(items, entry)
	}
	return map[string]any{"tools": items}
}

// BuildUpstreamRequest expands MCP `tools/call` arguments per the
// tool's ParamLocations into an http.Request whose URL host is the
// source REST APIID (so downstream rewriters see a coherent host).
//
// The function is parent-context-aware: the returned request inherits
// the parent's context, body, and trailers are not propagated (the
// adapter does not stream).
//
// Returned errors are user-facing — they are surfaced via the JSON-RPC
// `error` envelope.
func BuildUpstreamRequest(
	parent *http.Request,
	tool *oas.DerivedTool,
	restAPIID string,
	args map[string]any,
) (*http.Request, error) {

	if tool == nil {
		return nil, fmt.Errorf("nil tool")
	}

	path := tool.PathTemplate
	query := url.Values{}
	headers := http.Header{}
	var (
		bodyJSON any
		hasBody  bool
	)

	for argName, raw := range args {
		loc, known := tool.ParamLocations[argName]
		if !known {
			continue
		}
		switch {
		case loc == "path":
			path = strings.ReplaceAll(path, "{"+argName+"}", url.PathEscape(fmt.Sprint(raw)))
		case loc == "query":
			query.Set(argName, fmt.Sprint(raw))
		case loc == "header":
			headers.Set(argName, fmt.Sprint(raw))
		case loc == "body":
			bodyJSON = raw
			hasBody = true
		case strings.HasPrefix(loc, "body."):
			m, ok := bodyJSON.(map[string]any)
			if !hasBody {
				m = map[string]any{}
				bodyJSON = m
				hasBody = true
			} else if !ok {
				return nil, fmt.Errorf("argument %q cannot be combined with whole-body argument", argName)
			}
			m[argName] = raw
		}
	}

	if strings.Contains(path, "{") {
		return nil, fmt.Errorf("missing required path parameter in %q", tool.PathTemplate)
	}

	rawQuery := query.Encode()

	var body io.Reader
	if hasBody {
		buf, err := json.Marshal(bodyJSON)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(parent.Context(), tool.Method, path, body)
	if err != nil {
		return nil, err
	}
	if rawQuery != "" {
		req.URL.RawQuery = rawQuery
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Host = source REST APIID so downstream code that reads it sees a
	// coherent value (the loop primitive looks up handlers by APIID).
	req.URL.Host = restAPIID
	req.URL.Scheme = "http"
	req.Host = ""
	return req, nil
}

// Recorder buffers an http.Handler response into memory, capping the
// body at BodyTruncationBytes. Anything written past the cap is
// silently discarded and Truncated() returns true.
type Recorder struct {
	status   int
	header   http.Header
	body     bytes.Buffer
	overflow bool
}

// NewRecorder returns a Recorder ready to capture a single response.
func NewRecorder() *Recorder {
	return &Recorder{status: http.StatusOK, header: http.Header{}}
}

// Header satisfies http.ResponseWriter.
func (r *Recorder) Header() http.Header { return r.header }

// WriteHeader satisfies http.ResponseWriter.
func (r *Recorder) WriteHeader(s int) { r.status = s }

// Write satisfies http.ResponseWriter; truncates at BodyTruncationBytes.
func (r *Recorder) Write(b []byte) (int, error) {
	remaining := BodyTruncationBytes - r.body.Len()
	if remaining <= 0 {
		r.overflow = true
		return len(b), nil
	}
	if len(b) > remaining {
		r.body.Write(b[:remaining])
		r.overflow = true
		return len(b), nil
	}
	return r.body.Write(b)
}

// Status returns the HTTP status code the handler chose (defaults to 200).
func (r *Recorder) Status() int { return r.status }

// Body returns the captured body bytes (up to BodyTruncationBytes).
func (r *Recorder) Body() []byte { return r.body.Bytes() }

// ContentType returns the recorded Content-Type header (empty if unset).
func (r *Recorder) ContentType() string { return r.header.Get("Content-Type") }

// Truncated reports whether more bytes were written than the recorder
// retained.
func (r *Recorder) Truncated() bool { return r.overflow }

// ToolResultEnvelope wraps a recorded response as an MCP `result`
// envelope. `meta` is merged into `_meta`.
func ToolResultEnvelope(rec *Recorder) map[string]any {
	meta := map[string]any{
		"upstreamHttpStatus":  rec.Status(),
		"upstreamContentType": rec.ContentType(),
	}
	if rec.Truncated() {
		meta["truncated"] = true
	}
	return map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": string(rec.Body())},
		},
		"isError": rec.Status() >= 400,
		"_meta":   meta,
	}
}

// JSONRPCResult marshals a JSON-RPC 2.0 success envelope.
func JSONRPCResult(id any, result any) []byte {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"result":  result,
	})
	if err != nil {
		return JSONRPCError(id, JSONRPCInternalError, err.Error())
	}
	return b
}

// JSONRPCError marshals a JSON-RPC 2.0 error envelope.
func JSONRPCError(id any, code int, message string) []byte {
	b, err := json.Marshal(map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":null}`)
	}
	return b
}

// WriteJSON marshals v as application/json to w with status 200.
func WriteJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		return
	}
}
