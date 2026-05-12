// Package proxy implements the MCP-Proxy middleware core. The Handler
// type owns all the gateway-agnostic logic for the JSON-RPC dispatch
// described in RFC-API-TO-MCP-V7 §8.2 step 3 and §8.3:
//
//   - parse the JSON-RPC envelope on POST /<listenpath>
//   - dispatch initialize / notifications/initialized / tools/list /
//     ping / errors inline
//   - for tools/call: validate args against the tool's InputSchema,
//     reconstruct the upstream HTTP request (path / query / headers /
//     body), strip the agent's bearer, set the URL-rewrite target so
//     that the standard proxy step lands the call on either the
//     loopback tyk:// hop or the configured upstream
//
// This file does NOT import the gateway package. The Action enum tells
// the gateway-side shell middleware (gateway/mw_mcp_handler.go) whether
// to short-circuit the chain (ActionRespond — we wrote inline) or to
// hand off to the standard proxy step (ActionProxy).
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	oas "github.com/TykTechnologies/tyk/apidef/oas"
	mcppkg "github.com/TykTechnologies/tyk/internal/mcp"
)

// Action is the outcome of Handler.Dispatch. The gateway-side shell
// middleware uses it to decide between short-circuiting (StatusRespond)
// or letting the standard proxy step run.
type Action int

const (
	// ActionRespond means the handler already wrote a JSON-RPC response
	// to the ResponseWriter. The caller must short-circuit the
	// middleware chain.
	ActionRespond Action = iota

	// ActionProxy means the handler reconstructed the HTTP request and
	// stashed an URL-rewrite target. The caller must hand off to the
	// standard proxy step.
	ActionProxy
)

// URLRewriteSetter abstracts the gateway's ctxSetURLRewriteTarget so the
// proxy package can stay gateway-agnostic. The gateway shell injects a
// thin wrapper around ctxSetURLRewriteTarget that updates the request
// context in place.
type URLRewriteSetter func(r *http.Request, u *url.URL) *http.Request

// Mode picks between the two RFC §8.3 step 5 paths.
type Mode int

const (
	// ModeLoopback — the source is another in-process Tyk APIDef. The
	// handler injects X-Tyk-MCP-Context and rewrites the target to
	// tyk://<SourceAPIID>/<path>.
	ModeLoopback Mode = iota

	// ModeUpstream — the source is a third-party HTTPS upstream. The
	// handler does NOT inject X-Tyk-MCP-Context (no leak across a trust
	// boundary) and rewrites the target to <UpstreamURL>/<path>.
	ModeUpstream
)

// Handler is the gateway-agnostic core of the MCPHandler middleware.
// One Handler is shared per APIDef across all in-flight requests; it is
// safe for concurrent use because all of its fields are read-only after
// NewHandler returns. The compiled InputSchema cache is built lazily.
type Handler struct {
	cfg       *oas.MCPProxy
	validator Validator

	// catalogue is the runtime tool map built at proxy load by the
	// gateway shell via oas.DeriveSourceTools (RFC-API-TO-MCP-V8 §6.2).
	// Replaces V7's persisted Sources[*].Tools lookup. Keyed by the full
	// namespaced tool name "<source-slug>__<op-name>". Read-only after
	// NewHandler returns; the gateway swaps the entire Handler on reload
	// rather than mutating this map in place.
	catalogue map[string]*oas.MCPToolMapping

	// urlRewrite is the gateway-side hook that stashes the URL-rewrite
	// target on the request context.
	urlRewrite URLRewriteSetter

	// proxyAPIID is the APIDef id of the MCP Proxy itself.
	proxyAPIID string
}

// HandlerOption mutates a Handler at construction.
type HandlerOption func(*Handler)

// WithURLRewriteSetter wires the gateway's ctxSetURLRewriteTarget into
// the handler. Without this hook, ActionProxy will still be returned
// but the URL-rewrite target will not be set — only useful in tests.
func WithURLRewriteSetter(s URLRewriteSetter) HandlerOption {
	return func(h *Handler) { h.urlRewrite = s }
}

// WithProxyAPIID supplies the MCP Proxy APIDef id, embedded into the
// X-Tyk-MCP-Context header on loopback hops.
func WithProxyAPIID(id string) HandlerOption {
	return func(h *Handler) { h.proxyAPIID = id }
}

// WithCatalogue installs the derived tool catalogue. Required for tools/list
// and tools/call to return anything other than empty / -32601. The map
// must not be mutated after handing it to NewHandler.
func WithCatalogue(c map[string]*oas.MCPToolMapping) HandlerOption {
	return func(h *Handler) { h.catalogue = c }
}

// NewHandler builds a Handler over the given MCPProxy config and
// validator. The cfg must outlive the Handler.
func NewHandler(cfg *oas.MCPProxy, v Validator, opts ...HandlerOption) *Handler {
	h := &Handler{cfg: cfg, validator: v}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// jsonRPCRequest mirrors the wire envelope. We keep ID as json.RawMessage
// during parse so we can echo it back verbatim — JSON-RPC permits
// string, number, or null and the safest round-trip is byte-level.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// toolsCallParams is the params shape for `tools/call`.
type toolsCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// Dispatch is the single entrypoint. It reads & restores r.Body, then
// branches on the JSON-RPC method. For inline-response methods, it
// writes the response on w and returns ActionRespond. For tools/call it
// reconstructs the request and returns ActionProxy.
//
//nolint:gocyclo // dispatch table is intentionally explicit
func (h *Handler) Dispatch(w http.ResponseWriter, r *http.Request) (Action, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, mcppkg.JSONRPCParseError, mcppkg.ErrMsgParseError)
		return ActionRespond, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPCError(w, nil, mcppkg.JSONRPCParseError, mcppkg.ErrMsgParseError)
		return ActionRespond, nil
	}

	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidRequest, mcppkg.ErrMsgInvalidRequest)
		return ActionRespond, nil
	}

	switch req.Method {
	case "initialize":
		h.writeInitialize(w, req.ID)
		return ActionRespond, nil

	case "notifications/initialized":
		h.writeAck(w, req.ID)
		return ActionRespond, nil

	case mcppkg.MethodToolsList:
		h.writeToolsList(w, req.ID)
		return ActionRespond, nil

	case "ping":
		h.writePing(w, req.ID)
		return ActionRespond, nil

	case mcppkg.MethodToolsCall:
		return h.dispatchToolsCall(w, r, req)

	default:
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCMethodNotFound, "method not found: "+req.Method)
		return ActionRespond, nil
	}
}

func (h *Handler) protocolVersion() string {
	if h.cfg != nil && h.cfg.ProtocolVersion != "" {
		return h.cfg.ProtocolVersion
	}
	// Conservative default — actual MCP spec versions are dated strings;
	// the cfg-supplied value is authoritative in production.
	return "2025-06-18"
}

func (h *Handler) writeInitialize(w http.ResponseWriter, id json.RawMessage) {
	result := map[string]any{
		"protocolVersion": h.protocolVersion(),
		"capabilities": map[string]any{
			"tools": map[string]any{
				"listChanged": false,
			},
		},
	}
	writeJSONRPCResult(w, id, result)
}

func (h *Handler) writeAck(w http.ResponseWriter, id json.RawMessage) {
	// JSON-RPC notifications carry no id and expect no response. But if
	// the client sent an id (some MCP clients do), echo a minimal ack.
	if len(id) == 0 || string(id) == "null" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSONRPCResult(w, id, map[string]any{})
}

func (h *Handler) writePing(w http.ResponseWriter, id json.RawMessage) {
	writeJSONRPCResult(w, id, map[string]any{})
}

// writeToolsList enumerates the derived catalogue in deterministic order.
// PoC: single page, no cursor.
func (h *Handler) writeToolsList(w http.ResponseWriter, id json.RawMessage) {
	type toolDescriptor struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}

	tools := make([]toolDescriptor, 0, len(h.catalogue))
	names := make([]string, 0, len(h.catalogue))
	for k := range h.catalogue {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		t := h.catalogue[name]
		if t == nil {
			continue
		}
		tools = append(tools, toolDescriptor{
			Name:        t.ToolName,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	writeJSONRPCResult(w, id, map[string]any{"tools": tools})
}

// findTool returns the source binding and mapping for a given tool name.
// The mapping comes from the derived catalogue; the source is looked up on
// cfg.Sources by the slug recorded on the mapping.
func (h *Handler) findTool(name string) (*oas.MCPSource, *oas.MCPToolMapping) {
	if h.catalogue == nil || h.cfg == nil {
		return nil, nil
	}
	mapping, ok := h.catalogue[name]
	if !ok || mapping == nil {
		return nil, nil
	}
	for i := range h.cfg.Sources {
		if h.cfg.Sources[i].SourceSlug == mapping.SourceSlug {
			return &h.cfg.Sources[i], mapping
		}
	}
	return nil, mapping
}

// modeOf classifies a source.
func modeOf(src *oas.MCPSource) Mode {
	if src != nil && strings.EqualFold(src.BackendMode, "upstream") {
		return ModeUpstream
	}
	return ModeLoopback
}

// dispatchToolsCall implements RFC §8.3 step-by-step.
//
//nolint:gocyclo // RFC §8.3 prescribes a strict step-by-step sequence
func (h *Handler) dispatchToolsCall(w http.ResponseWriter, r *http.Request, req jsonRPCRequest) (Action, error) {
	// --- Step 0: parse params --------------------------------------------
	var p toolsCallParams
	if len(req.Params) == 0 {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidParams, mcppkg.ErrMsgMissingParams)
		return ActionRespond, nil
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidParams, mcppkg.ErrMsgInvalidParamsType)
		return ActionRespond, nil
	}
	if p.Name == "" {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidParams, mcppkg.ErrMsgMissingParamName)
		return ActionRespond, nil
	}
	if p.Arguments == nil {
		p.Arguments = map[string]interface{}{}
	}

	// --- Step 1: tool lookup ---------------------------------------------
	src, mapping := h.findTool(p.Name)
	if mapping == nil {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCMethodNotFound, "tool not found: "+p.Name)
		return ActionRespond, nil
	}

	// --- Step 2: schema validation ---------------------------------------
	if h.validator != nil && len(mapping.InputSchema) > 0 {
		argsBytes, err := json.Marshal(p.Arguments)
		if err != nil {
			writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInternalError, "marshal arguments: "+err.Error())
			return ActionRespond, nil
		}
		cs, err := h.validator.Compile(mapping.InputSchema)
		if err != nil {
			writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInternalError, "compile schema: "+err.Error())
			return ActionRespond, nil
		}
		if err := cs.Validate(argsBytes); err != nil {
			writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidParams, err.Error())
			return ActionRespond, nil
		}
	}

	// --- Step 3: reconstruct the request ---------------------------------
	method := strings.ToUpper(strings.TrimSpace(mapping.Method))
	if method == "" {
		method = http.MethodGet
	}

	pathStr, query, headerVals, bodyArgs, derr := buildRequestParts(mapping, p.Arguments)
	if derr != nil {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInvalidParams, derr.Error())
		return ActionRespond, nil
	}

	// Step 4: strip the agent's bearer.
	r.Header.Del("Authorization")

	// Apply reconstructed headers (after schema validation, so any CRLF
	// injection is in the validated values).
	for name, val := range headerVals {
		r.Header.Set(name, val)
	}

	// Step 5: inject X-Tyk-MCP-Context — loopback only.
	mode := modeOf(src)
	if mode == ModeLoopback {
		ctxHeader := mcpContextHeader{
			AgentID:    extractAgentID(r),
			ProxyAPIID: h.proxyAPIID,
			RequestID:  uuid.NewString(),
			ToolName:   mapping.ToolName,
			IssuedAt:   time.Now().Unix(),
		}
		if encoded, err := json.Marshal(ctxHeader); err == nil {
			r.Header.Set("X-Tyk-MCP-Context", string(encoded))
		}
	} else {
		// Defence in depth: never leak our metadata to a third-party
		// upstream, even if a prior hop set it.
		r.Header.Del("X-Tyk-MCP-Context")
	}

	// Step 6: stash JSON-RPC id and tool name for response wrap.
	var idAny any
	if len(req.ID) > 0 {
		_ = json.Unmarshal(req.ID, &idAny)
	}
	r2 := SetJSONRPCID(r, idAny)
	r2 = SetToolName(r2, mapping.ToolName)
	*r = *r2

	// Step 7: set URL-rewrite target.
	target, err := h.buildRewriteTarget(src, pathStr, query)
	if err != nil {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInternalError, err.Error())
		return ActionRespond, nil
	}
	if h.urlRewrite != nil {
		r3 := h.urlRewrite(r, target)
		if r3 != nil {
			*r = *r3
		}
	}

	// Mode (b) upstream: apply UpstreamCred outbound header.
	if mode == ModeUpstream && src.UpstreamCred != nil {
		switch strings.ToLower(src.UpstreamCred.AuthType) {
		case "header":
			if src.UpstreamCred.HeaderName != "" {
				r.Header.Set(src.UpstreamCred.HeaderName, src.UpstreamCred.SecretValue)
			}
		case "bearer":
			r.Header.Set("Authorization", "Bearer "+src.UpstreamCred.SecretValue)
		}
	}

	// Step 8: replace request method and body, fix CL/TE.
	bodyBytes, err := encodeBodyArgs(method, bodyArgs)
	if err != nil {
		writeJSONRPCError(w, req.ID, mcppkg.JSONRPCInternalError, "encode body: "+err.Error())
		return ActionRespond, nil
	}
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	r.Method = method
	if bodyBytes != nil {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		r.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		if r.Header.Get("Content-Type") == "" {
			r.Header.Set("Content-Type", "application/json")
		}
	} else {
		r.Body = http.NoBody
		r.ContentLength = 0
		r.Header.Del("Content-Length")
	}
	// Request-smuggling defence (RFC §13).
	r.Header.Del("Transfer-Encoding")
	r.TransferEncoding = nil

	// Update r.URL too, so anything that inspects it before the rewrite
	// target is consumed sees the correct path.
	if r.URL == nil {
		r.URL = &url.URL{}
	}
	r.URL.Path = pathStr
	if query != nil {
		r.URL.RawQuery = query.Encode()
	} else {
		r.URL.RawQuery = ""
	}

	return ActionProxy, nil
}

// buildRequestParts substitutes path/query/header arguments per
// ParamLocations. Body args are returned separately. CRLF/NUL in header
// values returns a non-nil error → caller maps to -32602.
//
//nolint:gocyclo // intentionally linear per RFC §8.3 step 3
func buildRequestParts(
	mapping *oas.MCPToolMapping,
	args map[string]interface{},
) (path string, query url.Values, headers map[string]string, body map[string]interface{}, err error) {
	path = mapping.PathTemplate
	query = url.Values{}
	headers = map[string]string{}
	body = map[string]interface{}{}

	for k, v := range args {
		loc, hasLoc := mapping.ParamLocations[k]
		if !hasLoc {
			body[k] = v
			continue
		}
		switch strings.ToLower(loc) {
		case "path":
			s := stringifyArg(v)
			placeholder := "{" + k + "}"
			if !strings.Contains(path, placeholder) {
				return "", nil, nil, nil, fmt.Errorf("path template missing placeholder for %q", k)
			}
			path = strings.ReplaceAll(path, placeholder, url.PathEscape(s))
		case "query":
			query.Set(k, stringifyArg(v))
		case "header":
			s := stringifyArg(v)
			if strings.ContainsAny(s, "\r\n\x00") {
				return "", nil, nil, nil, fmt.Errorf("invalid CRLF/NUL in header value for %q", k)
			}
			headers[k] = s
		case "body":
			body[k] = v
		default:
			body[k] = v
		}
	}

	// Reject any unsubstituted path placeholder (i.e. mapping declared a
	// path-bound param the caller did not supply, and InputSchema did
	// not catch it).
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return "", nil, nil, nil, fmt.Errorf("unsubstituted path placeholder in %q", path)
	}

	if len(query) == 0 {
		query = nil
	}
	if len(body) == 0 {
		body = nil
	}
	return path, query, headers, body, nil
}

// stringifyArg coerces a JSON-decoded value to its string wire form
// suitable for path / query / header substitution.
func stringifyArg(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers decode as float64 by default; preserve int form
		// where lossless.
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		// Maps, arrays, custom types — fall back to JSON encoding.
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// encodeBodyArgs JSON-encodes the body args when the method accepts a
// body. GET / HEAD / DELETE / OPTIONS / TRACE → no body.
func encodeBodyArgs(method string, body map[string]interface{}) ([]byte, error) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodDelete,
		http.MethodOptions, http.MethodTrace:
		return nil, nil
	}
	if len(body) == 0 {
		return nil, nil
	}
	return json.Marshal(body)
}

// buildRewriteTarget builds the URL-rewrite target per RFC §8.3 step 7.
func (h *Handler) buildRewriteTarget(src *oas.MCPSource, path string, query url.Values) (*url.URL, error) {
	if src == nil {
		return nil, fmt.Errorf("nil source")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	switch modeOf(src) {
	case ModeLoopback:
		// Tyk's loop primitive defaults to bypassing per-API and per-session
		// rate-limiting on the looped-into source (see
		// gateway/mw_api_rate_limit.go: ctxCheckLimits guard). Without
		// check_limits=true on the rewrite query, the source's chain runs but
		// its rate-limit middlewares short-circuit — defeating RFC §15.2
		// step 7's wedge proof that agent traffic participates in source-side
		// rate-limit machinery. We force-enable for MCP loopback hops.
		if query == nil {
			query = url.Values{}
		}
		query.Set("check_limits", "true")
		u := &url.URL{
			Scheme:   "tyk",
			Host:     src.SourceAPIID,
			Path:     path,
			RawQuery: query.Encode(),
		}
		return u, nil
	case ModeUpstream:
		base := strings.TrimRight(src.UpstreamURL, "/")
		full := base + path
		u, err := url.Parse(full)
		if err != nil {
			return nil, fmt.Errorf("parse upstream url: %w", err)
		}
		if query != nil {
			u.RawQuery = query.Encode()
		}
		return u, nil
	}
	return nil, fmt.Errorf("unknown backend mode: %q", src.BackendMode)
}

// mcpContextHeader is the §8.4 wire shape of X-Tyk-MCP-Context.
type mcpContextHeader struct {
	AgentID    string `json:"agent_id"`
	ProxyAPIID string `json:"proxy_apiid"`
	RequestID  string `json:"request_id"`
	ToolName   string `json:"tool_name"`
	IssuedAt   int64  `json:"issued_at"`
}

// extractAgentID best-effort lifts the agent identity from the request.
// In the gateway the Tyk auth middleware will have stamped a session
// onto the context; the proxy package does not import the session
// types, so we accept whatever is on a known string-typed context key
// or fall back to "". The gateway shell can override at a higher level
// if a richer source is needed.
func extractAgentID(r *http.Request) string {
	if r == nil {
		return ""
	}
	// We deliberately do not depend on Tyk session types here.
	// The gateway shell may set this header before invoking Dispatch
	// (rare); otherwise empty is acceptable for the PoC and is
	// documented in §8.4 ("metadata, not a trust input").
	return r.Header.Get("X-Tyk-Agent-Id")
}

// --- inline JSON-RPC writers ---------------------------------------------

func writeJSONRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"result":  result,
	}
	if len(id) > 0 {
		resp["id"] = json.RawMessage(id)
	} else {
		resp["id"] = nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	if len(id) > 0 {
		resp["id"] = json.RawMessage(id)
	} else {
		resp["id"] = nil
	}
	w.Header().Set("Content-Type", "application/json")
	// HTTP status: JSON-RPC traffic conventionally returns 200 for
	// transport-layer errors so the client unwraps the JSON-RPC envelope
	// rather than treating the call as an HTTP failure. The gateway-side
	// shell is free to override.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
