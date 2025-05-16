package core

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/model"
)

// ContextKey is the key type to be used for context interactions.
type ContextKey string

const (
	upstreamAuth = ContextKey("upstream-auth")
)

// SetContext updates the context of a request.
func SetContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}

// SetUpstreamAuth sets the header name to be used for upstream authentication.
func SetUpstreamAuth(r *http.Request, auth model.UpstreamAuthProvider) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, upstreamAuth, auth)
	SetContext(r, ctx)
}

// GetUpstreamAuth returns the header name to be used for upstream authentication.
func GetUpstreamAuth(r *http.Request) model.UpstreamAuthProvider {
	auth := r.Context().Value(upstreamAuth)
	if auth == nil {
		return nil
	}

	provider, ok := auth.(model.UpstreamAuthProvider)
	if !ok {
		return nil
	}

	return provider
}
