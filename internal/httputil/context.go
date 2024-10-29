package httputil

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

func CtxGetData(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(ContextData); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

func CtxSetData(r *http.Request, m map[string]interface{}) {
	if m == nil {
		panic("setting a nil context ContextData")
	}
	SetCtxValue(r, ContextData, m)
}

func SetCtxValue(r *http.Request, key, val interface{}) {
	SetContext(r, context.WithValue(r.Context(), key, val))
}

const (
	SessionData Key = iota
	// Deprecated: UpdateSession was used to trigger a session update, use *SessionData.Touch instead.
	UpdateSession
	AuthToken
	HashedAuthToken
	VersionData
	VersionName
	VersionDefault
	OrgSessionContext
	ContextData
	RetainHost
	TrackThisEndpoint
	DoNotTrackThisEndpoint
	UrlRewritePath
	RequestMethod
	OrigRequestURL
	LoopLevel
	LoopLevelLimit
	ThrottleLevel
	ThrottleLevelLimit
	Trace
	CheckLoopLimits
	UrlRewriteTarget
	TransformedRequestMethod
	Definition
	RequestStatus
	GraphQLRequest
	GraphQLIsWebSocketUpgrade
	OASOperation

	// CacheOptions holds cache options required for cache writer middleware.
	CacheOptions
	OASDefinition
)

type Key uint
