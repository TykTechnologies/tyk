package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

const (
	mcpAggregatorToolCallFailedMsg = "MCP aggregator could not call aggregated MCP proxy"

	// mcpAggregatorUpstreamErrorCode reports an aggregated MCP proxy that could
	// not answer, in the modern server-defined namespace the gateway uses for
	// upstream errors on 2026-07-28.
	mcpAggregatorUpstreamErrorCode = jsonrpcerrors.CodeModernUpstreamError
)

var (
	errMCPAggregatorUnknownTool = errors.New("unknown tool")
	// errMCPAggregatorAmbiguousName rejects params whose tool name more than
	// one decoder could read differently.
	errMCPAggregatorAmbiguousName = errors.New("params must carry exactly one name")
)

// mcpAggregatorUnavailableError reports an aggregated MCP proxy that could not
// serve a tool call; Reason is logged, never sent to the agent.
type mcpAggregatorUnavailableError struct {
	Reason string
}

func (e *mcpAggregatorUnavailableError) Error() string { return "upstream unavailable: " + e.Reason }

func mcpAggregatorUnavailable(format string, args ...any) error {
	return &mcpAggregatorUnavailableError{Reason: fmt.Sprintf(format, args...)}
}

// mcpAggregatorToolReply is an aggregated MCP proxy's answer to tools/call:
// either its raw result or its raw JSON-RPC error.
type mcpAggregatorToolReply struct {
	Result json.RawMessage
	Error  json.RawMessage
}

// serveToolsCall resolves a namespaced tool from the aggregator's
// configuration, forwards the call to the owning aggregated MCP proxy under
// the proxy's own tool name, and returns that proxy's answer unchanged. A
// JSON-RPC error from the proxy is answered with HTTP 200, as JSON-RPC errors
// are over Streamable HTTP: the proxy's own status describes the aggregator's
// hop, and a 401 or 429 relayed as is would send the agent into OAuth
// discovery or backoff against the aggregator.
func (m *MCPAggregatorMiddleware) serveToolsCall(w http.ResponseWriter, r *http.Request, state *httpctx.JSONRPCRoutingState) {
	d := mcpAggregatorDispatcher{gw: m.Gw, aggregator: m.Spec}
	name := mcp.ExtractStringField(state.Params, "name")

	upstream, tool, err := d.resolveTool(name)
	var reply *mcpAggregatorToolReply
	if err == nil {
		reply, err = d.callTool(r, upstream, tool, state.Params)
	}

	var unavailable *mcpAggregatorUnavailableError
	switch {
	case err != nil && mcpAggregatorClientGone(r):
		log.WithFields(logrus.Fields{
			"aggregator_api_id": m.Spec.APIID,
			"upstream_api_id":   upstream.APIID,
			"alias":             upstream.Alias,
			"tool":              name,
		}).Debug("MCP aggregator cancelled tool call: the agent cancelled the request")
	case err != nil && errors.Is(r.Context().Err(), context.DeadlineExceeded):
		timeout := mcpAggregatorTimeout(m.Spec, r)
		log.WithFields(logrus.Fields{
			"aggregator_api_id": m.Spec.APIID,
			"upstream_api_id":   upstream.APIID,
			"alias":             upstream.Alias,
			"tool":              name,
			"reason":            fmt.Sprintf("timeout after %s", timeout),
		}).Warn(mcpAggregatorToolCallFailedMsg)
		writeMCPAggregatorError(w, state.ID, http.StatusGatewayTimeout, mcpAggregatorUpstreamErrorCode,
			fmt.Sprintf("upstream timeout: aggregated MCP proxy %q did not answer within %s", upstream.Alias, timeout))
	case errors.Is(err, errMCPAggregatorUnknownTool):
		writeMCPAggregatorError(w, state.ID, http.StatusBadRequest, mcp.JSONRPCInvalidParams, fmt.Sprintf("unknown tool %q", name))
	case errors.Is(err, errMCPAggregatorAmbiguousName):
		writeMCPAggregatorError(w, state.ID, http.StatusBadRequest, mcp.JSONRPCInvalidParams, err.Error())
	case errors.As(err, &unavailable):
		log.WithFields(logrus.Fields{
			"aggregator_api_id": m.Spec.APIID,
			"upstream_api_id":   upstream.APIID,
			"alias":             upstream.Alias,
			"tool":              name,
			"reason":            unavailable.Reason,
		}).Warn(mcpAggregatorToolCallFailedMsg)
		writeMCPAggregatorError(w, state.ID, http.StatusServiceUnavailable, mcpAggregatorUpstreamErrorCode,
			fmt.Sprintf("upstream unavailable: aggregated MCP proxy %q", upstream.Alias))
	case err != nil:
		writeMCPAggregatorError(w, state.ID, http.StatusInternalServerError, mcp.JSONRPCInternalError, "MCP aggregator could not call the tool")
	case reply.Error != nil:
		writeMCPAggregatorRaw(w, http.StatusOK, state.ID, "error", reply.Error)
	default:
		writeMCPAggregatorRaw(w, http.StatusOK, state.ID, "result", reply.Result)
	}
}

// resolveTool splits a namespaced tool name at the first separator, since
// aliases cannot contain underscores, and checks from configuration alone
// that the alias names an admitted aggregated MCP proxy. It makes no upstream
// call, so each tools/call costs the proxy exactly one request against its
// rate limits; a tool the proxy does not have is rejected by the proxy.
func (d mcpAggregatorDispatcher) resolveTool(name string) (mcpaggregator.Upstream, string, error) {
	alias, tool, found := strings.Cut(name, mcpaggregator.NamespaceSeparator)
	if !found || alias == "" || tool == "" {
		return mcpaggregator.Upstream{}, "", errMCPAggregatorUnknownTool
	}
	ext := d.aggregator.OAS.GetTykMCPAggregatorExtension()
	if ext == nil {
		return mcpaggregator.Upstream{}, "", errMCPAggregatorUnknownTool
	}
	var upstream mcpaggregator.Upstream
	for _, ref := range ext.Upstreams {
		if ref.Alias == alias {
			upstream = mcpaggregator.Upstream{APIID: ref.APIID, Alias: ref.Alias, Tools: ref.Tools}
			break
		}
	}
	if upstream.Alias == "" {
		return mcpaggregator.Upstream{}, "", errMCPAggregatorUnknownTool
	}

	if !mcpAggregatorSelects(upstream, tool) {
		return upstream, "", errMCPAggregatorUnknownTool
	}
	if status := classifyMCPAggregatorUpstream(d.aggregator.OrgID, d.gw.getApiSpec(upstream.APIID)); status != mcpAggregatorUpstreamAdmitted {
		return upstream, "", mcpAggregatorUnavailable("%s", status.String())
	}
	return upstream, tool, nil
}

// mcpAggregatorSelects reports whether the aggregator exposes tool of an
// aggregated MCP proxy. Every tool is exposed until tool selection (TT-18770)
// applies upstream.Tools here, rejecting deselected tools without an upstream
// call, and in listUpstreamTools.
func mcpAggregatorSelects(_ mcpaggregator.Upstream, _ string) bool {
	return true
}

// isMCPUnknownToolError reports a proxy's unknown-tool rejection: -32602 with
// the "unknown tool" wording of the MCP SDKs and the specification's example,
// which the gateway's API-to-MCP adapter and remote go-sdk servers both send.
func isMCPUnknownToolError(raw json.RawMessage) bool {
	var rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	return json.Unmarshal(raw, &rpcErr) == nil && rpcErr.Code == mcp.JSONRPCInvalidParams &&
		strings.HasPrefix(strings.ToLower(rpcErr.Message), "unknown tool")
}

// callTool forwards a tools/call to an aggregated MCP proxy. Only the name in
// params changes, to the proxy's own tool name; arguments, _meta and every
// other field keep their bytes. Mcp-Name mirrors the new name, and the
// agent's Mcp-Param-* headers travel with the call.
func (d mcpAggregatorDispatcher) callTool(parent *http.Request, upstream mcpaggregator.Upstream, tool string, params json.RawMessage) (*mcpAggregatorToolReply, error) {
	spec, err := d.upstreamSpec(upstream.APIID)
	if err != nil {
		return nil, mcpAggregatorUnavailable("%s", err.Error())
	}
	encodedTool, err := json.Marshal(tool)
	if err != nil {
		return nil, err
	}
	forwarded, err := replaceJSONObjectField(params, "name", encodedTool)
	if err != nil {
		return nil, errMCPAggregatorAmbiguousName
	}
	body := make([]byte, 0, len(forwarded)+64)
	body = append(body, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`...)
	body = append(body, forwarded...)
	body = append(body, '}')

	extra := http.Header{}
	for name, values := range parent.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), mcp.HeaderParamPrefix) {
			extra[name] = values
		}
	}
	extra.Set(mcp.HeaderName, mcp.EncodeMirroredHeader(tool))

	rec, err := d.exchange(parent, spec, mcp.MethodToolsCall, body, extra, d.loopTrust(spec))
	if err != nil {
		return nil, mcpAggregatorUnavailable("tools/call failed: %s", err.Error())
	}
	if detail := mcpAggregatorVersionMismatch(mcp.MethodToolsCall, rec.statusCode, rec.header, rec.body.Bytes()); detail != "" {
		return nil, mcpAggregatorUnavailable("version mismatch: does not support MCP version %s: %s", mcp.ModernProtocolVersion, detail)
	}
	if rec.statusCode >= http.StatusInternalServerError {
		return nil, mcpAggregatorUnavailable("tools/call failed with HTTP %d", rec.statusCode)
	}

	message := rec.body.Bytes()
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec.header.Get(headerContentType))), "text/event-stream") {
		if message, err = mcpAggregatorEventStreamResponse(message); err != nil {
			return nil, mcpAggregatorUnavailable("tools/call failed: %s", err.Error())
		}
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(message, &resp) != nil {
		return nil, mcpAggregatorUnavailable("tools/call failed with HTTP %d: invalid JSON-RPC response", rec.statusCode)
	}
	switch {
	case len(resp.Error) > 0 && string(resp.Error) != "null" && isMCPUnknownToolError(resp.Error):
		return nil, errMCPAggregatorUnknownTool
	case len(resp.Error) > 0 && string(resp.Error) != "null":
		return &mcpAggregatorToolReply{Error: resp.Error}, nil
	case rec.statusCode >= http.StatusBadRequest || len(resp.Result) == 0:
		return nil, mcpAggregatorUnavailable("tools/call failed with HTTP %d: JSON-RPC response has no result", rec.statusCode)
	}
	return &mcpAggregatorToolReply{Result: resp.Result}, nil
}

// replaceJSONObjectField replaces the value of the top-level field key in a
// JSON object and keeps every other byte of the object as it was.
//
// Ingress already refuses a request whose params.name is duplicated or spelled
// in another case (mcp.RequestEnvelope.UnmarshalJSON, through
// validateOwnedJSONObject, answers -32700), so every decoder reads the same
// name. This function does not rely on that: an object holding key more than
// once, or a case variant of it, fails rather than forward a name a proxy
// could read differently.
func replaceJSONObjectField(object json.RawMessage, key string, value []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(object))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("params must be a JSON object")
	}
	var out []byte
	last, seen := 0, 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		field, ok := tok.(string)
		if !ok {
			return nil, errors.New("params must be a JSON object")
		}
		if !strings.EqualFold(field, key) {
			continue
		}
		if seen++; seen > 1 || field != key {
			return nil, fmt.Errorf("params must carry %q exactly once", key)
		}
		end := int(dec.InputOffset())
		start := end - len(raw)
		out = append(out, object[last:start]...)
		out = append(out, value...)
		last = end
	}
	if seen == 0 {
		return nil, fmt.Errorf("params must carry %q", key)
	}
	return append(out, object[last:]...), nil
}

// writeMCPAggregatorRaw writes a JSON-RPC response whose result or error member
// carries the given bytes unchanged.
func writeMCPAggregatorRaw(w http.ResponseWriter, status int, id any, member string, raw json.RawMessage) {
	encodedID, err := json.Marshal(id)
	if err != nil {
		encodedID = []byte("null")
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	prefix := fmt.Appendf(nil, `{"jsonrpc":%q,"id":%s,%q:`, apidef.JsonRPC20, encodedID, member)
	for _, part := range [][]byte{prefix, raw, []byte("}\n")} {
		if _, err := w.Write(part); err != nil {
			// The status line is already sent, so a failed write, usually a
			// client that went away, can only be logged.
			log.WithError(err).Warn("MCP aggregator could not write the JSON-RPC response")
			return
		}
	}
}
