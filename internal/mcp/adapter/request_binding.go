package adapter

import (
	"context"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type requestBindingKey struct{}
type requestBinding struct {
	current context.Context
	owner   string
}

const requestBindingExtraKey = "tyk.internal.mcp.request-binding"

// WithRequestBinding carries Gateway-verified admission to the SDK boundary.
// Callers must authenticate the public request and verify its internal pairing
// before constructing this binding. HTTP headers never supply its provenance.
func WithRequestBinding(ctx, current context.Context, owner string) context.Context {
	return context.WithValue(ctx, requestBindingKey{}, requestBinding{current, owner})
}

// CurrentRequestContext returns the current HTTP message's trusted context. The
// SDK callback context itself may retain values from session initialization.
func CurrentRequestContext(ctx context.Context) (context.Context, bool) {
	binding, ok := ctx.Value(requestBindingKey{}).(requestBinding)
	return binding.current, ok && binding.current != nil && binding.owner != ""
}

func requestBindingFromExtra(req *mcpsdk.CallToolRequest) (requestBinding, bool) {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return requestBinding{}, false
	}
	binding, ok := req.Extra.TokenInfo.Extra[requestBindingExtraKey].(requestBinding)
	return binding, ok && binding.current != nil && binding.owner != ""
}

func withSDKRequestBinding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, original *http.Request) {
		binding, ok := original.Context().Value(requestBindingKey{}).(requestBinding)
		if !ok || binding.current == nil || binding.owner == "" {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// v1.6's public metadata setter requires bearer syntax. This local placeholder
		// only enters that setter; the verifier trusts private admission, not its text.
		// Restore every original header before SDK dispatch, without mutating caller
		// headers or exposing the placeholder to logging or REST execution.
		local := original.Clone(original.Context())
		local.Header.Set("Authorization", "Bearer tyk-internal-mcp-metadata")
		verifier := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
			info := auth.TokenInfo{Expiration: time.Now().Add(time.Minute)}
			if trusted := auth.TokenInfoFromContext(original.Context()); trusted != nil {
				info = *trusted
				info.Scopes = append([]string(nil), trusted.Scopes...)
			}
			extra := make(map[string]any, len(info.Extra)+1)
			for key, value := range info.Extra {
				extra[key] = value
			}
			extra[requestBindingExtraKey] = binding
			info.Extra = extra
			info.UserID = binding.owner
			return &info, nil
		}
		auth.RequireBearerToken(verifier, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header = original.Header.Clone()
			next.ServeHTTP(w, r)
		})).ServeHTTP(w, local)
	})
}
