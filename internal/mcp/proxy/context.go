package proxy

import (
	"context"
	"net/http"
)

// ctxKeyJSONRPCID is an unexported context-key type used to stash the
// JSON-RPC `id` field of an in-flight `tools/call` envelope. The
// MCPResponseWrap response middleware (Phase B2) reads it to restore the
// id on the wrapped response.
type ctxKeyJSONRPCID struct{}

// ctxKeyToolName is an unexported context-key type used to stash the full
// namespaced tool name of an in-flight `tools/call`. Read by the response
// wrap and the structured-log emitter.
type ctxKeyToolName struct{}

// SetJSONRPCID stashes the JSON-RPC envelope id on the request context and
// returns a request bound to the new context. The id is preserved as `any`
// because JSON-RPC permits string, number, or null.
func SetJSONRPCID(r *http.Request, id any) *http.Request {
	if r == nil {
		return r
	}
	ctx := context.WithValue(r.Context(), ctxKeyJSONRPCID{}, id)
	return r.WithContext(ctx)
}

// GetJSONRPCID retrieves the JSON-RPC envelope id previously stashed by
// SetJSONRPCID. Returns nil and false if absent.
func GetJSONRPCID(r *http.Request) (any, bool) {
	if r == nil {
		return nil, false
	}
	v := r.Context().Value(ctxKeyJSONRPCID{})
	if v == nil {
		return nil, false
	}
	return v, true
}

// SetToolName stashes the full namespaced tool name on the request context.
func SetToolName(r *http.Request, name string) *http.Request {
	if r == nil {
		return r
	}
	ctx := context.WithValue(r.Context(), ctxKeyToolName{}, name)
	return r.WithContext(ctx)
}

// GetToolName retrieves the tool name previously stashed by SetToolName.
// Returns empty string and false if absent.
func GetToolName(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	v := r.Context().Value(ctxKeyToolName{})
	if v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
