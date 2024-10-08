package ctxutil

import (
	"context"
	"github.com/TykTechnologies/tyk/internal/proxy"
	"net/http"
)

const (
	upstreamAuth = "upstream-auth"
)

func SetContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}

// SetUpstreamAuth sets the header name to be used for upstream authentication.
func SetUpstreamAuth(r *http.Request, auth proxy.UpstreamAuthProvider) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, upstreamAuth, auth)
	SetContext(r, ctx)
}

// GetUpstreamAuth returns the header name to be used for upstream authentication.
func GetUpstreamAuth(r *http.Request) proxy.UpstreamAuthProvider {
	auth := r.Context().Value(upstreamAuth)
	if auth == nil {
		return nil
	}

	provider, ok := auth.(proxy.UpstreamAuthProvider)
	if !ok {
		return nil
	}

	return provider
}
