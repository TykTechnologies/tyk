package gateway

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
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// mcpAdapterBodyTruncationBytes is the maximum size of an upstream
// response body the adapter inlines into the MCP `result.content[]`
// envelope. Bodies larger than this are truncated and the response is
// tagged with `_meta.truncated: true`.
const mcpAdapterBodyTruncationBytes = 1 << 20 // 1 MiB

// MCP JSON-RPC method names handled inline by the adapter. (mcp package
// declares tools/* etc. but does not yet declare these utility methods.)
const (
	mcpMethodInitialize = "initialize"
	mcpMethodPing       = "ping"
)

// mcpAdapterProtocolVersion is the MCP protocol version this adapter
// advertises in its `initialize` result. Keep in sync with the version
// the rest of the gateway supports.
const mcpAdapterProtocolVersion = "2025-06-18"

// handleAdapterInline answers initialize / ping / tools/list inline for
// a synthetic adapter spec. Returns true if the method was handled and
// the JSON-RPC envelope has been written to w; the caller must then
// return middleware.StatusRespond.
//
// Returns false if the method is not one we answer inline (the caller
// should fall through to the regular VEM/loop dispatch path).
func (m *JSONRPCMiddleware) handleAdapterInline(w http.ResponseWriter, r *http.Request, rpcReq *JSONRPCRequest) bool {
	if m.Spec == nil || !m.Spec.IsSyntheticMCPAdapter {
		return false
	}

	switch rpcReq.Method {
	case mcpMethodInitialize:
		m.writeAdapterResult(w, r, rpcReq.ID, adapterInitializeResult(m.Spec))
		return true
	case mcpMethodPing:
		m.writeAdapterResult(w, r, rpcReq.ID, map[string]any{})
		return true
	case mcp.MethodToolsList:
		m.writeAdapterResult(w, r, rpcReq.ID, adapterToolsListResult(m.Spec))
		return true
	}
	return false
}

// handleAdapterToolsCall translates a `tools/call` envelope into an
// HTTP request against the paired REST API, stamps the trust descriptor
// so MCPLoopAuthBypass on the REST side can short-circuit auth, and
// dispatches via the `tyk://` loop primitive.
//
// On success the upstream response is wrapped as an MCP `result` envelope
// and written to w; the caller must return middleware.StatusRespond.
// Returns true if the call was handled (success or error), false if the
// caller should fall through.
func (gw *Gateway) handleAdapterToolsCall(
	w http.ResponseWriter,
	r *http.Request,
	spec *APISpec,
	rpcReq *JSONRPCRequest,
) bool {
	if spec == nil || !spec.IsSyntheticMCPAdapter {
		return false
	}
	if rpcReq.Method != mcp.MethodToolsCall {
		return false
	}

	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(rpcReq.Params) > 0 {
		if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
			writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCInvalidParams, "invalid tools/call params: "+err.Error())
			return true
		}
	}
	if params.Name == "" {
		writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCInvalidParams, "tools/call requires a tool name")
		return true
	}

	tool := findDerivedTool(spec.DerivedTools, params.Name)
	if tool == nil {
		writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCMethodNotFound, "unknown tool: "+params.Name)
		return true
	}

	upstreamReq, err := gw.buildAdapterUpstreamRequest(r, spec, tool, params.Arguments)
	if err != nil {
		writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCInternalError, err.Error())
		return true
	}

	gw.apisMu.RLock()
	proxyAPIID := gw.mcpPairing[spec.SourceRESTAPIID]
	gw.apisMu.RUnlock()
	if proxyAPIID == "" {
		writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCInternalError, "no MCP proxy paired with this REST API")
		return true
	}

	httpctx.SetMCPLoopFromPairedProxy(upstreamReq, &httpctx.MCPLoopTrust{
		ProxyAPIID:   proxyAPIID,
		RESTAPIID:    spec.SourceRESTAPIID,
		AdapterAPIID: spec.APIID,
	})

	rec := newAdapterRecorder()
	handler, _, ok := gw.findInternalHttpHandlerByNameOrID(spec.SourceRESTAPIID)
	if !ok {
		writeAdapterError(w, r, rpcReq.ID, mcp.JSONRPCInternalError, "paired REST API handler not found")
		return true
	}
	handler.ServeHTTP(rec, upstreamReq)

	writeAdapterToolResult(w, r, rpcReq.ID, rec)
	return true
}

// findDerivedTool returns the DerivedTool with the given name, or nil.
func findDerivedTool(tools []oas.DerivedTool, name string) *oas.DerivedTool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

// adapterInitializeResult is the `initialize` result envelope advertised
// to MCP clients.
func adapterInitializeResult(spec *APISpec) map[string]any {
	return map[string]any{
		"protocolVersion": mcpAdapterProtocolVersion,
		"serverInfo": map[string]any{
			"name":    spec.Name,
			"version": "1.0",
		},
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
	}
}

// adapterToolsListResult builds the `tools/list` result from the
// adapter's DerivedTools.
func adapterToolsListResult(spec *APISpec) map[string]any {
	items := make([]map[string]any, 0, len(spec.DerivedTools))
	for _, t := range spec.DerivedTools {
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

// buildAdapterUpstreamRequest expands MCP tool arguments per the tool's
// ParamLocations and returns an http.Request whose URL is a `tyk://`
// loop into the paired REST APISpec.
func (gw *Gateway) buildAdapterUpstreamRequest(
	parent *http.Request,
	spec *APISpec,
	tool *oas.DerivedTool,
	args map[string]any,
) (*http.Request, error) {
	path := tool.PathTemplate
	query := url.Values{}
	headers := http.Header{}
	var bodyJSON map[string]any

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
			if m, ok := raw.(map[string]any); ok {
				bodyJSON = m
			} else {
				return nil, fmt.Errorf("argument %q must be an object when body is whole-body", argName)
			}
		case strings.HasPrefix(loc, "body."):
			if bodyJSON == nil {
				bodyJSON = map[string]any{}
			}
			bodyJSON[argName] = raw
		}
	}

	if strings.Contains(path, "{") {
		return nil, fmt.Errorf("missing required path parameter in %q", tool.PathTemplate)
	}

	rawQuery := query.Encode()
	loopURL := &url.URL{
		Scheme:   "tyk",
		Host:     oas.AdapterLoopHost(spec.SourceRESTAPIID),
		Path:     path,
		RawQuery: rawQuery,
	}
	_ = loopURL // loop dispatch goes via the handler we look up below;
	// the URL on the request itself only needs Host/Path for downstream
	// rewriters that may consult them.

	var body io.Reader
	if bodyJSON != nil {
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
		req.Header.Set(headerContentType, contentTypeJSON)
	}
	// Make sure the rewritten URL host is the source REST API so any
	// downstream code that reads it sees a coherent value.
	req.URL.Host = spec.SourceRESTAPIID
	req.URL.Scheme = "http"
	req.Host = ""
	return req, nil
}

// adapterRecorder is a tiny http.ResponseWriter that buffers the
// upstream REST chain's response so the adapter can wrap it as an MCP
// tool result envelope.
type adapterRecorder struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func newAdapterRecorder() *adapterRecorder {
	return &adapterRecorder{status: http.StatusOK, header: http.Header{}}
}

func (r *adapterRecorder) Header() http.Header { return r.header }
func (r *adapterRecorder) WriteHeader(s int)   { r.status = s }
func (r *adapterRecorder) Write(b []byte) (int, error) {
	if r.body.Len() >= mcpAdapterBodyTruncationBytes {
		return len(b), nil // silently drop further bytes once over the cap
	}
	remaining := mcpAdapterBodyTruncationBytes - r.body.Len()
	if len(b) > remaining {
		r.body.Write(b[:remaining])
		return len(b), nil
	}
	return r.body.Write(b)
}

// writeAdapterToolResult wraps the recorded REST chain response in the
// MCP `result` envelope.
func writeAdapterToolResult(w http.ResponseWriter, r *http.Request, id any, rec *adapterRecorder) {
	content := map[string]any{
		"type": "text",
		"text": rec.body.String(),
	}
	result := map[string]any{
		"content": []any{content},
		"isError": rec.status >= 400,
	}
	if rec.body.Len() >= mcpAdapterBodyTruncationBytes {
		result["_meta"] = map[string]any{
			"truncated":           true,
			"upstreamHttpStatus":  rec.status,
			"upstreamContentType": rec.header.Get(headerContentType),
		}
	} else {
		result["_meta"] = map[string]any{
			"upstreamHttpStatus":  rec.status,
			"upstreamContentType": rec.header.Get(headerContentType),
		}
	}
	envelope := map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"result":  result,
	}
	writeAdapterJSON(w, envelope)
	_ = r
	_ = middleware.StatusRespond
}

// writeAdapterError writes a JSON-RPC error envelope for adapter inline
// failures (unknown tool, malformed args, etc.).
func writeAdapterError(w http.ResponseWriter, r *http.Request, id any, code int, msg string) {
	_ = r
	envelope := map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	}
	writeAdapterJSON(w, envelope)
}

// writeAdapterResult writes a JSON-RPC result envelope for inline-handled
// methods (initialize / ping / tools/list).
func (m *JSONRPCMiddleware) writeAdapterResult(w http.ResponseWriter, r *http.Request, id any, result any) {
	_ = r
	envelope := map[string]any{
		"jsonrpc": apidef.JsonRPC20,
		"id":      id,
		"result":  result,
	}
	writeAdapterJSON(w, envelope)
}

// writeAdapterJSON marshals v and writes it as application/json to w. Errors
// during write are logged but not surfaced — the chain has already
// committed to responding.
func writeAdapterJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		mainLog.WithError(err).Error("MCP adapter: failed to marshal response envelope")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		mainLog.WithError(err).Debug("MCP adapter: response write error")
	}
}
