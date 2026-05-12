package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/httputil"
	mcppkg "github.com/TykTechnologies/tyk/internal/mcp"
	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

// MCPHandlerMiddleware is the gateway shell around mcpproxy.Handler.
// It dispatches the incoming JSON-RPC envelope on an MCP-Proxy APIDef
// per RFC-API-TO-MCP-V7 §8.2 step 3:
//
//   - inline-response methods (initialize / tools/list / ping / errors)
//     are written directly and the chain is short-circuited via
//     middleware.StatusRespond.
//   - tools/call reconstructs the request, sets the URL-rewrite target,
//     and returns http.StatusOK so the standard proxy step picks it up.
//
// EnabledForSpec is true iff the OAS x-tyk-api-gateway.server.mcpProxy
// extension is present on the spec.
type MCPHandlerMiddleware struct {
	*BaseMiddleware

	once      sync.Once
	handler   *mcpproxy.Handler
	catalogue map[string]*oas.MCPToolMapping
}

// Name returns the middleware name.
func (m *MCPHandlerMiddleware) Name() string { return "MCPHandler" }

// EnabledForSpec gates the middleware on the presence of the MCPProxy
// OAS extension on the spec.
func (m *MCPHandlerMiddleware) EnabledForSpec() bool {
	if m == nil || m.Spec == nil {
		return false
	}
	if !m.Spec.IsOAS {
		return false
	}
	ext := m.Spec.OAS.GetTykExtension()
	if ext == nil {
		return false
	}
	return ext.Server.MCPProxy != nil
}

// init lazily builds the underlying mcpproxy.Handler. EnabledForSpec
// having returned true is a precondition. Builds the derived tool
// catalogue (RFC-API-TO-MCP-V8 §6.2) by walking each source: for loopback
// sources, reads the source APIDef's OAS from the gateway registry; for
// upstream sources, parses the proxy-attached UpstreamOAS.
func (m *MCPHandlerMiddleware) init() {
	m.once.Do(func() {
		ext := m.Spec.OAS.GetTykExtension()
		cfg := ext.Server.MCPProxy
		m.catalogue = buildMCPProxyCatalogue(m.Gw, cfg, m.Logger())
		setter := mcpproxy.URLRewriteSetter(func(r *http.Request, u *url.URL) *http.Request {
			ctxSetURLRewriteTarget(r, u)
			return r
		})
		m.handler = mcpproxy.NewHandler(
			cfg,
			mcpproxy.DefaultValidator(),
			mcpproxy.WithProxyAPIID(m.Spec.APIID),
			mcpproxy.WithURLRewriteSetter(setter),
			mcpproxy.WithCatalogue(m.catalogue),
		)
	})
}

// ProcessRequest implements the TykMiddleware interface. It must be
// inserted AFTER auth (so the agent's bearer has already been
// validated) and BEFORE the standard proxy step.
//
//nolint:staticcheck // ST1008: middleware interface requires (error, int) return order
func (m *MCPHandlerMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Only POST application/json is in scope. Anything else is either
	// the dashboard hitting a non-MCP listenpath (we should pass through)
	// or a misuse.
	if r.Method != http.MethodPost {
		return nil, http.StatusOK
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return nil, http.StatusOK
	}

	// Streaming requests are out-of-scope per RFC §8.3 step 8.
	if httputil.IsStreamingRequest(r) {
		writeMCPHandlerJSONRPCError(w, mcppkg.JSONRPCInvalidParams,
			"streaming request bodies are not supported")
		return nil, middleware.StatusRespond
	}

	m.init()
	if m.handler == nil {
		// Defensive — EnabledForSpec should have prevented this.
		return nil, http.StatusOK
	}

	// Pre-parse the envelope so we know whether to emit the §14 log
	// (only `tools/call` is in scope) and what tool name to attribute
	// when Dispatch writes an inline error before reaching the tool
	// lookup. peekToolCall reads + restores r.Body.
	peeked := peekToolCall(r)
	logTC := peeked.parseOK && peeked.method == mcppkg.MethodToolsCall

	var (
		start time.Time
		cw    *captureWriter
		dw    http.ResponseWriter = w
	)
	if logTC {
		start = time.Now()
		cw = &captureWriter{ResponseWriter: w}
		dw = cw
	}

	action, err := m.handler.Dispatch(dw, r)

	if logTC {
		ext := m.Spec.OAS.GetTykExtension()
		var cfg = ext.Server.MCPProxy
		src := findSource(cfg, m.catalogue, peeked.toolName)
		authPath := deriveAuthPath(m.Gw, src)
		captured := cw.buf.Bytes()
		outcome := outcomeFromAction(action, err, captured)
		emitMCPToolCallLog(
			m.Spec.APIID,
			src,
			peeked.toolName,
			agentIDFromRequest(r),
			authPath,
			nowMS(start),
			outcome,
		)
	}

	if err != nil {
		// Dispatch logs internally; surface as -32603 inline.
		writeMCPHandlerJSONRPCError(w, mcppkg.JSONRPCInternalError, err.Error())
		return nil, middleware.StatusRespond
	}

	switch action {
	case mcpproxy.ActionRespond:
		// Handler already wrote the response.
		return nil, middleware.StatusRespond
	case mcpproxy.ActionProxy:
		// RFC §14: map tool_name → analytics.MCPStats.PrimitiveName for
		// backward compat with existing pump consumers. The new §14 log
		// fields ride alongside, not on, MCPStats.
		if logTC && peeked.toolName != "" {
			ctxSetMCPPrimitiveName(r, peeked.toolName)
		}
		// Rebuild the now-replaced body for any downstream re-reads
		// (mirrors gateway/mw_jsonrpc.go's nopCloseRequestBody usage).
		nopCloseRequestBody(r)
		return nil, http.StatusOK
	default:
		// Unreachable.
		return nil, http.StatusOK
	}
}

// writeMCPHandlerJSONRPCError is a minimal local writer used only for
// gateway-level pre-handler failures (streaming-request rejection,
// internal errors). The handler package writes its own envelopes for
// in-flight dispatch errors.
func writeMCPHandlerJSONRPCError(w http.ResponseWriter, code int, message string) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	body := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":` +
		intToStr(code) + `,"message":` + jsonString(message) + `}}`)
	_, _ = w.Write(body)
}

func intToStr(i int) string {
	// Avoid pulling strconv just for this one call; the constants we
	// pass here are bounded and small.
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func jsonString(s string) string {
	// Minimal JSON-string escape — the message strings we pass are
	// internal constants, but defend against future callers.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
