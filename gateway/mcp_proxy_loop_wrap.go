package gateway

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	mcpproxy "github.com/TykTechnologies/tyk/internal/mcp/proxy"
)

// mcpLoopCaptureWriter buffers the bytes written by a tyk:// loop dispatch so
// that MCPHandler's caller can wrap the upstream payload in a JSON-RPC 2.0
// envelope. It is installed only when the in-flight request was identified as
// an MCP tools/call (i.e. MCPHandler stashed a JSON-RPC id on the context);
// non-MCP loops are unaffected and short-circuit via shouldWrapMCPLoopResponse.
//
// We exist because the standard TykResponseHandler chain runs inside
// reverse_proxy.go after a real HTTP upstream call. tyk:// loops bypass the
// reverse proxy entirely (DummyProxyHandler.ServeHTTP dispatches the looped-into
// chain directly to w), so MCPProxyResponseWrap never sees mode (a) responses.
// Mode (b) outbound HTTPS still uses the response-handler path. RFC §8.2 step 5.
type mcpLoopCaptureWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newMCPLoopCaptureWriter() *mcpLoopCaptureWriter {
	return &mcpLoopCaptureWriter{header: http.Header{}, status: http.StatusOK}
}

func (w *mcpLoopCaptureWriter) Header() http.Header { return w.header }

func (w *mcpLoopCaptureWriter) WriteHeader(code int) { w.status = code }

func (w *mcpLoopCaptureWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

// shouldWrapMCPLoopResponse reports whether the in-flight request is an MCP
// tools/call that needs envelope wrapping after the loop completes.
func shouldWrapMCPLoopResponse(r *http.Request) (any, bool) {
	id, ok := mcpproxy.GetJSONRPCID(r)
	return id, ok
}

// emitMCPLoopEnvelope writes the wrapped JSON-RPC envelope from a captured
// loop response onto the real ResponseWriter. SSE responses bypass wrapping
// (mirrors res_handler_mcp_proxy_wrap.go's SSE bypass).
func emitMCPLoopEnvelope(w http.ResponseWriter, captured *mcpLoopCaptureWriter, id any) {
	if ct := captured.header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		// SSE — pass the captured stream through as-is.
		for k, vs := range captured.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if captured.status != 0 {
			w.WriteHeader(captured.status)
		}
		_, _ = w.Write(captured.body.Bytes())
		return
	}

	body := captured.body.Bytes()
	var envelope []byte
	switch {
	case captured.status >= 200 && captured.status < 300:
		envelope = buildSuccessEnvelope(id, captured.header.Get("Content-Type"), body)
	default:
		envelope = buildErrorEnvelope(id, captured.status, body, captured.header.Get("Retry-After"))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(envelope)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(envelope)
}
