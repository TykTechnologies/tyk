package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
	"github.com/TykTechnologies/tyk/user"
)

// maxWrapBodyBytes is the upper bound on the upstream response body we will
// read for 2xx wrapping. The RFC does not set an explicit cap for the success
// path; 10 MiB is large enough to cover realistic API payloads while
// preventing pathological memory blow-ups from a misbehaving upstream.
const maxWrapBodyBytes = 10 * 1024 * 1024

// maxBodyExcerptBytes is the cap on the `body_excerpt` field of error
// envelopes. Per RFC-API-TO-MCP-V7 §8.5 this MUST be ≤ 1 KiB.
const maxBodyExcerptBytes = 1024

// MCPProxyResponseWrap wraps the upstream HTTP response of an MCP `tools/call`
// invocation into a JSON-RPC 2.0 envelope, per RFC-API-TO-MCP-V7 §8.2 step 5
// and §8.5. 2xx upstream responses become a successful `result` envelope;
// non-2xx responses become a tool-execution error (`isError: true`) envelope
// returned with HTTP 200 OK.
//
// The handler is a no-op unless the request was identified as an MCP
// `tools/call` (i.e. JSON-RPC routing state is present and carries an ID).
// SSE responses are passed through unchanged.
type MCPProxyResponseWrap struct {
	BaseTykResponseHandler
}

// Base returns the embedded base handler.
func (h *MCPProxyResponseWrap) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

// Name identifies this handler in logs and middleware chains.
func (h *MCPProxyResponseWrap) Name() string {
	return "MCPProxyResponseWrap"
}

// Init stores the API spec on the embedded base handler.
func (h *MCPProxyResponseWrap) Init(_ any, spec *APISpec) error {
	h.Spec = spec
	return nil
}

// Enabled returns true when the spec carries the MCPProxy extension on Server.
// The C1 registration site (createResponseMiddlewareChain) already gates on
// the same predicate; we re-check here because responseMWAppendEnabled calls
// Enabled() during chain assembly and short-circuits when it returns false.
func (h *MCPProxyResponseWrap) Enabled() bool {
	if h.Spec == nil || !h.Spec.IsOAS {
		return false
	}
	ext := h.Spec.OAS.GetTykExtension()
	return ext != nil && ext.Server.MCPProxy != nil
}

// HandleResponse wraps the upstream response into a JSON-RPC envelope.
func (h *MCPProxyResponseWrap) HandleResponse(_ http.ResponseWriter, res *http.Response, req *http.Request, _ *user.SessionState) error {
	// SSE bypass — never read an event-stream body, it would block forever.
	if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		return nil
	}

	// Only wrap if MCPHandler stashed a tools/call JSON-RPC id on this request.
	id, ok := mcpproxy.GetJSONRPCID(req)
	if !ok {
		return nil
	}

	body, readErr := readCappedBody(res, maxWrapBodyBytes)

	var envelope []byte
	switch {
	case readErr != nil:
		// Defensive: produce a generic upstream_error envelope rather than
		// surfacing a transport error.
		envelope = buildErrorEnvelope(id, res.StatusCode, body, readErr.Error())
	case res.StatusCode >= 200 && res.StatusCode < 300:
		envelope = buildSuccessEnvelope(id, res.Header.Get("Content-Type"), body)
	default:
		envelope = buildErrorEnvelope(id, res.StatusCode, body, res.Header.Get("Retry-After"))
	}

	res.Body = io.NopCloser(bytes.NewReader(envelope))
	res.ContentLength = int64(len(envelope))
	res.Header.Set("Content-Length", strconv.Itoa(len(envelope)))
	res.Header.Set("Content-Type", "application/json")
	// Per RFC §8.5: tool-execution errors are 200 OK with isError: true.
	res.StatusCode = http.StatusOK
	res.Status = http.StatusText(http.StatusOK)
	// Drop any Content-Encoding the upstream may have set; we replaced the body.
	res.Header.Del("Content-Encoding")

	return nil
}

// readCappedBody reads up to limit bytes from res.Body and closes it. Any
// error during read is returned alongside whatever bytes were already read.
func readCappedBody(res *http.Response, limit int64) ([]byte, error) {
	if res.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit))
	res.Body.Close()
	return body, err
}

// buildSuccessEnvelope produces a JSON-RPC 2.0 result envelope wrapping a
// 2xx upstream response. structuredContent is populated only when the
// upstream Content-Type indicates JSON and the body is parseable.
func buildSuccessEnvelope(id any, contentType string, body []byte) []byte {
	result := map[string]any{
		"content": []any{
			map[string]any{
				"type": "text",
				"text": string(body),
			},
		},
		"isError": false,
	}

	if isJSONContentType(contentType) && len(body) > 0 {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err == nil {
			result["structuredContent"] = parsed
		}
	}

	return marshalEnvelope(id, result)
}

// buildErrorEnvelope produces a JSON-RPC 2.0 result envelope with
// isError: true, mapping the upstream HTTP status to a `kind` per §8.5.
//
// retryAfterRaw is the raw `Retry-After` header value (only meaningful when
// status == 429). When called from the defensive read-error branch the
// caller passes the underlying error string; we do not attempt to parse it
// as a Retry-After.
func buildErrorEnvelope(id any, status int, body []byte, retryAfterRaw string) []byte {
	kind, shortReason := mapStatusToKind(status)

	structured := map[string]any{
		"kind": kind,
	}
	if status > 0 {
		structured["upstream_status"] = status
	}
	structured["body_excerpt"] = redactExcerpt(body)

	if status == http.StatusTooManyRequests && retryAfterRaw != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(retryAfterRaw)); err == nil && secs >= 0 {
			structured["retry_after_seconds"] = secs
		}
	}

	result := map[string]any{
		"isError": true,
		"content": []any{
			map[string]any{
				"type": "text",
				"text": shortReason,
			},
		},
		"structuredContent": structured,
	}
	return marshalEnvelope(id, result)
}

// mapStatusToKind returns the (kind, short human reason) tuple per §8.5.
func mapStatusToKind(status int) (string, string) {
	switch status {
	case http.StatusUnauthorized:
		return "auth_revoked", "upstream authentication failed (401)"
	case http.StatusForbidden:
		return "forbidden", "upstream forbade the request (403)"
	case http.StatusNotFound:
		return "not_found", "upstream resource not found (404)"
	case http.StatusTooManyRequests:
		return "rate_limited", "upstream rate limited the request (429)"
	}
	if status >= 500 && status <= 599 {
		return "upstream_5xx", "upstream server error"
	}
	return "upstream_error", "upstream returned an error"
}

// marshalEnvelope serialises a JSON-RPC 2.0 result envelope. Failures fall
// back to a hard-coded internal-error envelope so the handler never panics
// or returns malformed bytes to the client.
func marshalEnvelope(id any, result map[string]any) []byte {
	out, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
	if err != nil {
		// Should be unreachable: the inputs are JSON-safe by construction.
		return []byte(`{"jsonrpc":"2.0","id":null,"result":{"isError":true,"content":[{"type":"text","text":"internal error"}],"structuredContent":{"kind":"upstream_error"}}}`)
	}
	return out
}

// isJSONContentType reports whether ct names a JSON-ish media type.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "application/json" || ct == "text/json" {
		return true
	}
	// application/<vendor>+json
	return strings.HasPrefix(ct, "application/") && strings.HasSuffix(ct, "+json")
}

// redactExcerpt trims surrounding whitespace and truncates body to
// ≤ maxBodyExcerptBytes (1 KiB per RFC §8.5). Despite the name, this does
// NOT perform any credential-pattern redaction — it is pure trim+truncate.
// The RFC does not specify a redaction algorithm; size-capping the excerpt
// is the documented minimum to bound information disclosure on the error
// path. If pattern-based redaction becomes a requirement it should be
// added here, not at a layer further down.
func redactExcerpt(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	// Strip leading/trailing whitespace before truncating so the excerpt is
	// useful even when the upstream pretty-prints with leading newlines.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > maxBodyExcerptBytes {
		trimmed = trimmed[:maxBodyExcerptBytes]
	}
	return string(trimmed)
}
