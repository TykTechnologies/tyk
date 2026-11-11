package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/TykTechnologies/tyk/internal/mcp"
	mcpaggregator "github.com/TykTechnologies/tyk/internal/mcp/aggregator"
)

var errMCPAggregatorUpstreamNotLoaded = errors.New("not loaded on this gateway")

// mcpAggregatorMaxUpstreamResponseBytes caps one buffered aggregated proxy
// response when the gateway sets no max_response_body_size.
const mcpAggregatorMaxUpstreamResponseBytes = 10 << 20

// mcpAggregatorDispatcher sends JSON-RPC requests from an aggregator to its
// aggregated MCP proxies through their in-process middleware chains.
type mcpAggregatorDispatcher struct {
	gw         *Gateway
	aggregator *APISpec
}

// call sends one modern-protocol JSON-RPC request to an aggregated MCP proxy
// and returns the raw JSON-RPC result.
func (d mcpAggregatorDispatcher) call(parent *http.Request, upstream mcpaggregator.Upstream, method string, params map[string]any) (json.RawMessage, error) {
	spec, err := d.upstreamSpec(upstream.APIID)
	if err != nil {
		return nil, err
	}
	return d.send(parent, spec, method, params, d.loopTrust(spec))
}

// upstreamSpec returns the loaded spec of an aggregated MCP proxy this
// aggregator admits.
func (d mcpAggregatorDispatcher) upstreamSpec(apiID string) (*APISpec, error) {
	spec := d.gw.getApiSpec(apiID)
	if spec == nil || !d.gw.mcpAggregatorIndex.Allows(d.aggregator.APIID, apiID) {
		return nil, errMCPAggregatorUpstreamNotLoaded
	}
	return spec, nil
}

func (d mcpAggregatorDispatcher) loopTrust(spec *APISpec) *mcpAggregatorLoopTrust {
	return &mcpAggregatorLoopTrust{
		OrgID:           d.aggregator.OrgID,
		AggregatorAPIID: d.aggregator.APIID,
		UpstreamAPIID:   spec.APIID,
	}
}

// send runs one JSON-RPC request through an aggregated MCP proxy's chain under
// the given loop trust. A response showing that the proxy does not serve
// 2026-07-28 is reported as an *mcpAggregatorVersionMismatchError.
func (d mcpAggregatorDispatcher) send(parent *http.Request, spec *APISpec, method string, params map[string]any, trust *mcpAggregatorLoopTrust) (json.RawMessage, error) {
	body, err := mcpAggregatorRequestBody(method, params)
	if err != nil {
		return nil, err
	}
	rec, err := d.exchange(parent, spec, method, body, nil, trust)
	if err != nil {
		return nil, err
	}
	if detail := mcpAggregatorVersionMismatch(method, rec.statusCode, rec.header, rec.body.Bytes()); detail != "" {
		return nil, &mcpAggregatorVersionMismatchError{Method: method, Detail: detail}
	}
	if rec.statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("%s failed with HTTP %d", method, rec.statusCode)
	}
	return parseMCPAggregatorResult(method, rec.header.Get(headerContentType), rec.body.Bytes())
}

// exchange runs one JSON-RPC request body through an aggregated MCP proxy's
// chain under the given loop trust, with the MCP headers for method and any
// extra headers, and returns the buffered response.
func (d mcpAggregatorDispatcher) exchange(parent *http.Request, spec *APISpec, method string, body []byte, extra http.Header, trust *mcpAggregatorLoopTrust) (*mcpAggregatorResponseRecorder, error) {
	if d.gw.apisHandlesByID == nil {
		return nil, errMCPAggregatorUpstreamNotLoaded
	}
	chain, ok := d.gw.apisHandlesByID.Load(spec.APIID)
	if !ok {
		return nil, errMCPAggregatorUpstreamNotLoaded
	}
	handler, ok := chain.(*ChainObject)
	if !ok || handler.ThisHandler == nil {
		return nil, errMCPAggregatorUpstreamNotLoaded
	}

	req, err := http.NewRequestWithContext(mcpAggregatorUpstreamRequestContext(parent.Context()), http.MethodPost, spec.Proxy.ListenPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = parent.Host
	req.RemoteAddr = parent.RemoteAddr
	for name, values := range extra {
		req.Header[name] = append([]string(nil), values...)
	}
	req.Header.Set(headerContentType, contentTypeJSON)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, method)
	ctxSetMCPAggregatorLoopTrust(req, trust)

	rec := &mcpAggregatorResponseRecorder{bufferedResponseWriter: newBufferedResponseWriter(), limit: d.maxResponseBytes()}
	handler.ThisHandler.ServeHTTP(rec, req)
	if rec.exceeded {
		return nil, fmt.Errorf("response exceeds %d bytes", rec.limit)
	}
	return rec, nil
}

func (d mcpAggregatorDispatcher) maxResponseBytes() int {
	if limit := d.gw.GetConfig().HttpServerOptions.MaxResponseBodySize; limit > 0 {
		return int(limit)
	}
	return mcpAggregatorMaxUpstreamResponseBytes
}

// mcpAggregatorResponseRecorder buffers an aggregated proxy response up to a
// limit and records whether the response went past it.
type mcpAggregatorResponseRecorder struct {
	*bufferedResponseWriter
	limit    int
	exceeded bool
}

func (w *mcpAggregatorResponseRecorder) Write(data []byte) (int, error) {
	if w.exceeded || w.body.Len()+len(data) > w.limit {
		w.exceeded = true
		return len(data), nil
	}
	return w.bufferedResponseWriter.Write(data)
}

// mcpAggregatorUpstreamContext keeps the caller's cancellation but none of its
// request-scoped values, so the aggregated proxy's chain starts clean.
type mcpAggregatorUpstreamContext struct {
	context.Context
}

func (mcpAggregatorUpstreamContext) Value(any) any { return nil }

// mcpAggregatorUpstreamRequestContext keeps only the caller's cancellation and
// trace span, so upstream spans join the aggregator's trace.
func mcpAggregatorUpstreamRequestContext(parent context.Context) context.Context {
	return oteltrace.ContextWithSpan(mcpAggregatorUpstreamContext{parent}, oteltrace.SpanFromContext(parent))
}

func mcpAggregatorRequestBody(method string, params map[string]any) ([]byte, error) {
	withMeta := make(map[string]any, len(params)+1)
	for key, value := range params {
		withMeta[key] = value
	}
	withMeta["_meta"] = map[string]any{
		mcp.MetaKeyProtocolVersion:    mcp.ModernProtocolVersion,
		mcp.MetaKeyClientCapabilities: map[string]any{},
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  withMeta,
	})
}

type mcpAggregatorJSONRPCResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *JSONRPCError   `json:"error"`
}

func parseMCPAggregatorResult(method, contentType string, body []byte) (json.RawMessage, error) {
	message := body
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/event-stream") {
		var err error
		if message, err = mcpAggregatorEventStreamResponse(body); err != nil {
			return nil, fmt.Errorf("%s failed: %w", method, err)
		}
	}

	var resp mcpAggregatorJSONRPCResponse
	if err := json.Unmarshal(message, &resp); err != nil {
		return nil, fmt.Errorf("%s failed: invalid JSON-RPC response", method)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%s failed with JSON-RPC error %d: %s", method, resp.Error.Code, resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("%s failed: JSON-RPC response has no result", method)
	}
	return resp.Result, nil
}

// mcpAggregatorEventStreamResponse returns the JSON-RPC response carried by a
// Streamable HTTP event stream, skipping notifications and requests.
func mcpAggregatorEventStreamResponse(body []byte) ([]byte, error) {
	var data []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), len(body)+1)
	flush := func() []byte {
		if len(data) == 0 {
			return nil
		}
		event := []byte(strings.Join(data, "\n"))
		data = data[:0]
		var probe struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(event, &probe) == nil && (probe.Result != nil || probe.Error != nil) {
			return event
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if event := flush(); event != nil {
				return event, nil
			}
			continue
		}
		if value, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(value, " "))
		}
	}
	if event := flush(); event != nil {
		return event, nil
	}
	return nil, errors.New("event stream has no JSON-RPC response")
}
