package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	oas "github.com/TykTechnologies/tyk/apidef/oas"
	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
)

// mcpToolCallLogMsg is the structured-log message field for the per
// `tools/call` event defined in RFC-API-TO-MCP-V7 §14.
const mcpToolCallLogMsg = "mcp.tool_call"

// auth_path values per RFC §14.
const (
	mcpAuthPathCallerAuth      = "mcp_caller_auth"
	mcpAuthPathUpstreamCred    = "upstream_cred"
	mcpAuthPathKeylessLoopback = "keyless_loopback"
	mcpAuthPathUnknown         = "unknown"
)

// outcome values per RFC §14.
const (
	mcpOutcomeSuccess       = "success"
	mcpOutcomeJSONRPCError  = "json_rpc_error"
	mcpOutcomeUpstreamError = "upstream_error" // not captured at this scope; see doc below
	mcpOutcomeInternalError = "internal_error"
)

// peekedToolCall is the minimum we extract by re-parsing the JSON-RPC
// envelope before Dispatch consumes it. We only care whether method ==
// "tools/call" and the tool name; the parse is best-effort and on
// failure we treat the event as a non-tools/call (skip logging) or as a
// tool-name-unknown json_rpc_error if method was tools/call.
type peekedToolCall struct {
	method   string
	toolName string
	parseOK  bool
}

// peekToolCall reads & restores r.Body and returns whatever we can parse
// out of it. Mirrors mcpproxy.Handler.Dispatch's read+restore pattern so
// the body stays consumable for the real dispatch downstream.
func peekToolCall(r *http.Request) peekedToolCall {
	if r == nil || r.Body == nil {
		return peekedToolCall{}
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return peekedToolCall{}
	}
	var env struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return peekedToolCall{}
	}
	return peekedToolCall{
		method:   env.Method,
		toolName: env.Params.Name,
		parseOK:  true,
	}
}

// captureWriter is a thin tee that records the response body bytes
// alongside writing them through to the wrapped ResponseWriter. We use
// it to detect whether an inline JSON-RPC response was a result or an
// error after Dispatch returns ActionRespond.
type captureWriter struct {
	http.ResponseWriter
	buf bytes.Buffer
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.buf.Write(p)
	return c.ResponseWriter.Write(p)
}

// findSource resolves the source binding for a tool name via the derived
// catalogue (RFC-API-TO-MCP-V8 §6.2). The catalogue entry carries the
// source slug; we walk cfg.Sources by slug.
func findSource(cfg *oas.MCPProxy, catalogue map[string]*oas.MCPToolMapping, toolName string) *oas.MCPSource {
	if cfg == nil || toolName == "" || catalogue == nil {
		return nil
	}
	mapping, ok := catalogue[toolName]
	if !ok || mapping == nil {
		return nil
	}
	for i := range cfg.Sources {
		if cfg.Sources[i].SourceSlug == mapping.SourceSlug {
			return &cfg.Sources[i]
		}
	}
	return nil
}

// deriveAuthPath classifies the auth path per RFC §14.
//
// The middleware does not have a direct view of which authenticator
// established the session, but it has full access to the MCP-Proxy
// config plus the gateway's API map, which is enough:
//
//   - upstream mode               -> upstream_cred
//   - loopback + source has AcceptMCPLoopCallers=true   -> mcp_caller_auth
//   - loopback + source is keyless                       -> keyless_loopback
//   - anything we cannot decide                          -> unknown
//
// Source spec lookup miss should be impossible after the C2 admission
// gate but is handled defensively as "unknown".
func deriveAuthPath(gw *Gateway, src *oas.MCPSource) string {
	if src == nil {
		return mcpAuthPathUnknown
	}
	if strings.EqualFold(src.BackendMode, "upstream") {
		return mcpAuthPathUpstreamCred
	}
	// loopback
	if gw == nil || src.SourceAPIID == "" {
		return mcpAuthPathUnknown
	}
	srcSpec := gw.getApiSpec(src.SourceAPIID)
	if srcSpec == nil || srcSpec.APIDefinition == nil {
		return mcpAuthPathUnknown
	}
	if srcSpec.IsOAS {
		if ext := srcSpec.OAS.GetTykExtension(); ext != nil && ext.Server.AcceptMCPLoopCallers {
			return mcpAuthPathCallerAuth
		}
	}
	if srcSpec.APIDefinition.UseKeylessAccess {
		return mcpAuthPathKeylessLoopback
	}
	return mcpAuthPathUnknown
}

// modeStringOf returns the wire-form mode label.
func modeStringOf(src *oas.MCPSource) string {
	if src != nil && strings.EqualFold(src.BackendMode, "upstream") {
		return "upstream"
	}
	return "loopback"
}

// inlineResponseHadError peeks at the captured ResponseWriter bytes and
// returns true iff the JSON-RPC envelope carries an "error" field. Used
// only for ActionRespond paths; on parse failure returns false (treat as
// non-error rather than misclassifying).
func inlineResponseHadError(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	var env struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(buf, &env); err != nil {
		return false
	}
	return len(env.Error) > 0
}

// emitMCPToolCallLog writes the §14 structured log line. Field set is
// fixed by the RFC; missing/unknown values are emitted as empty string
// rather than omitted, so log consumers can rely on the schema.
//
// Outcome capture caveat (intentional, PoC scope per RFC §14):
//
//	`upstream_error` is NOT captured here. The gateway-side shell sees
//	only the dispatch decision (ActionRespond → inline result/error;
//	ActionProxy → handed off to the standard proxy step). Errors that
//	occur during the proxy step itself (5xx from the loopback target,
//	upstream HTTP failures) are translated into JSON-RPC errors by the
//	response-wrap middleware in a later phase (B2 / D). Capturing
//	`upstream_error` would require either piggy-backing on the response
//	wrap (touches a forbidden file in this sub-task) or a deferred-emit
//	finalizer, which is explicitly deferred to GA per §14's
//	"dashboards / runbooks / cross-repo MCPStats bump deferred to GA".
//	This helper therefore reports `success` for ActionProxy hand-off,
//	`json_rpc_error` for inline error envelopes, and `internal_error`
//	for the rare Dispatch-returned-err path.
func emitMCPToolCallLog(
	proxyAPIID string,
	src *oas.MCPSource,
	toolName string,
	agentID string,
	authPath string,
	durationMS float64,
	outcome string,
) {
	srcSlug := ""
	if src != nil {
		srcSlug = src.SourceSlug
	}
	log.WithFields(logrus.Fields{
		"proxy_apiid": proxyAPIID,
		"source_slug": srcSlug,
		"tool_name":   toolName,
		"mode":        modeStringOf(src),
		"agent_id":    agentID,
		"auth_path":   authPath,
		"duration_ms": durationMS,
		"outcome":     outcome,
	}).Info(mcpToolCallLogMsg)
}

// nowMS returns a duration in fractional milliseconds since `start`.
// Extracted so tests can substitute a deterministic clock if needed.
func nowMS(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

// agentIDFromRequest mirrors the proxy package's best-effort extraction.
// Header-only for the PoC; the synthetic session built by MCPCallerAuth
// downstream is not visible at this point in the chain because the
// MCP-Proxy APIDef itself runs the agent's auth, not MCPCallerAuth.
func agentIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get("X-Tyk-Agent-Id")
}

// outcomeFromAction maps the dispatch action + captured response buffer
// to an outcome string. Returns "" when the call should not be logged
// (i.e. method != tools/call and tool name unknown — handled by caller).
func outcomeFromAction(action mcpproxy.Action, dispatchErr error, captured []byte) string {
	if dispatchErr != nil {
		return mcpOutcomeInternalError
	}
	switch action {
	case mcpproxy.ActionProxy:
		return mcpOutcomeSuccess
	case mcpproxy.ActionRespond:
		if inlineResponseHadError(captured) {
			return mcpOutcomeJSONRPCError
		}
		return mcpOutcomeSuccess
	}
	return mcpOutcomeInternalError
}
