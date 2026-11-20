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
	"github.com/TykTechnologies/tyk/request"
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
	// budget, when set, bounds the bytes buffered from one aggregated proxy's
	// responses. It is used by one goroutine at a time.
	budget *mcpAggregatorByteBudget
}

// mcpAggregatorByteBudget is one aggregated MCP proxy's share of the
// catalogue byte budget for one tools/list.
type mcpAggregatorByteBudget struct {
	share int
	used  int
}

// newResponseRecorder buffers one response up to the gateway's response size
// limit, or up to what is left of the budget when that is less, so the
// response being read and those already read together stay within the share.
func (d mcpAggregatorDispatcher) newResponseRecorder() *mcpAggregatorResponseRecorder {
	rec := &mcpAggregatorResponseRecorder{bufferedResponseWriter: newBufferedResponseWriter(), limit: d.maxResponseBytes()}
	if d.budget != nil && d.budget.share-d.budget.used < rec.limit {
		rec.limit = d.budget.share - d.budget.used
		rec.budgeted = true
	}
	return rec
}

// recorded reports a response that went past its limit, and otherwise
// charges the response to the budget.
func (d mcpAggregatorDispatcher) recorded(rec *mcpAggregatorResponseRecorder) error {
	if rec.exceeded {
		if rec.budgeted {
			return fmt.Errorf("responses exceed the %d byte share of the catalogue byte budget", d.budget.share)
		}
		return fmt.Errorf("response exceeds %d bytes", rec.limit)
	}
	if d.budget != nil {
		d.budget.used += rec.body.Len()
	}
	return nil
}

// call sends one modern-protocol JSON-RPC request to an aggregated MCP proxy
// and returns the raw JSON-RPC result.
func (d mcpAggregatorDispatcher) call(parent *http.Request, upstream mcpaggregator.Upstream, method string, params map[string]any) (json.RawMessage, error) {
	spec := d.gw.getApiSpec(upstream.APIID)
	if spec == nil || !d.gw.mcpAggregatorIndex.Allows(d.aggregator.APIID, upstream.APIID) {
		return nil, errMCPAggregatorUpstreamNotLoaded
	}
	return d.send(parent, spec, method, params, &mcpAggregatorLoopTrust{
		OrgID:           d.aggregator.OrgID,
		AggregatorAPIID: d.aggregator.APIID,
		UpstreamAPIID:   spec.APIID,
	})
}

// send runs one JSON-RPC request through an aggregated MCP proxy's chain under
// the given loop trust. A response showing that the proxy does not serve
// 2026-07-28 is reported as an *mcpAggregatorVersionMismatchError.
func (d mcpAggregatorDispatcher) send(parent *http.Request, spec *APISpec, method string, params map[string]any, trust *mcpAggregatorLoopTrust) (json.RawMessage, error) {
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

	body, err := mcpAggregatorRequestBody(method, params)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // G704: served in-process by the proxy's own chain below, never sent over the network.
	req, err := http.NewRequestWithContext(mcpAggregatorUpstreamRequestContext(parent.Context(), request.RealIP(parent)), http.MethodPost, spec.Proxy.ListenPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = parent.Host
	req.RemoteAddr = parent.RemoteAddr
	req.Header.Set(headerContentType, contentTypeJSON)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, mcp.ModernProtocolVersion)
	req.Header.Set(mcp.HeaderMethod, method)
	ctxSetMCPAggregatorLoopTrust(req, trust)

	rec := d.newResponseRecorder()
	handler.ThisHandler.ServeHTTP(rec, req)
	if err := d.recorded(rec); err != nil {
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
	// budgeted is set when the limit is what is left of a byte budget.
	budgeted bool
}

func (w *mcpAggregatorResponseRecorder) Write(data []byte) (int, error) {
	if w.exceeded || w.body.Len()+len(data) > w.limit {
		w.exceeded = true
		return len(data), nil
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	// Append to the in-memory buffer directly: the bytes are parsed by the
	// aggregator and never reach a client connection.
	return w.body.Write(data)
}

// mcpAggregatorClientIPContextKey is the context key request.RealIP reads
// before any header or the remote address.
const mcpAggregatorClientIPContextKey = "remote_addr"

// mcpAggregatorUpstreamContext keeps the caller's cancellation and client IP
// but none of its other request-scoped values, so the aggregated proxy's chain
// starts clean.
type mcpAggregatorUpstreamContext struct {
	context.Context
	clientIP string
}

func (c mcpAggregatorUpstreamContext) Value(key any) any {
	if key == mcpAggregatorClientIPContextKey {
		return c.clientIP
	}
	return nil
}

// mcpAggregatorUpstreamRequestContext keeps only the caller's cancellation,
// trace span and client IP. Upstream spans join the aggregator's trace, and
// request.RealIP in the aggregated proxy's chain returns clientIP, the address
// the aggregator resolved for its caller, so the proxy's IP access control
// sees the agent's address and not the load balancer's in front of it.
func mcpAggregatorUpstreamRequestContext(parent context.Context, clientIP string) context.Context {
	return oteltrace.ContextWithSpan(mcpAggregatorUpstreamContext{Context: parent, clientIP: clientIP}, oteltrace.SpanFromContext(parent))
}

func mcpAggregatorRequestBody(method string, params map[string]any) ([]byte, error) {
	withMeta := make(map[string]any)
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
