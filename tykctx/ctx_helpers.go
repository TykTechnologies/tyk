package tykctx

import (
	"net/http"
	"github.com/TykTechnologies/tyk/apidef"
	"context"
	"github.com/TykTechnologies/tyk/session"
)

const (
	SessionData = iota
	AuthHeaderValue
	VersionData
	VersionKeyContext
	OrgSessionContext
	ContextData
	RetainHost
	TrackThisEndpoint
	DoNotTrackThisEndpoint
)

// TODO: Don't modify http.Request values in-place. We must right now
// because our middleware design doesn't pass around http.Request
// pointers, so we have no way to modify the pointer in a middleware.
//
// If we ever redesign middlewares - or if we find another workaround -
// revisit this.
func SetContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}
func setCtxValue(r *http.Request, key, val interface{}) {
	SetContext(r, context.WithValue(r.Context(), key, val))
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
	setCtxValue(r, ContextData, m)
}

func CtxGetSession(r *http.Request) *session.SessionState {
	if v := r.Context().Value(SessionData); v != nil {
		return v.(*session.SessionState)
	}
	return nil
}

func CtxSetSession(r *http.Request, s *session.SessionState) {
	if s == nil {
		panic("setting a nil context SessionData")
	}
	setCtxValue(r, SessionData, s)
}

func CtxGetAuthToken(r *http.Request) string {
	if v := r.Context().Value(AuthHeaderValue); v != nil {
		return v.(string)
	}
	return ""
}

func CtxSetAuthToken(r *http.Request, t string) {
	if t == "" {
		panic("setting a nil context AuthHeaderValue")
	}
	setCtxValue(r, AuthHeaderValue, t)
}

func CtxGetTrackedPath(r *http.Request) string {
	if v := r.Context().Value(TrackThisEndpoint); v != nil {
		return v.(string)
	}
	return ""
}

func CtxSetTrackedPath(r *http.Request, p string) {
	if p == "" {
		panic("setting a nil context TrackThisEndpoint")
	}
	setCtxValue(r, TrackThisEndpoint, p)
}

func CtxGetDoNotTrack(r *http.Request) bool {
	return r.Context().Value(DoNotTrackThisEndpoint) == true
}

func CtxSetDoNotTrack(r *http.Request, b bool) {
	setCtxValue(r, DoNotTrackThisEndpoint, b)
}

func CtxGetVersionInfo(r *http.Request) *apidef.VersionInfo {
	if v := r.Context().Value(VersionData); v != nil {
		return v.(*apidef.VersionInfo)
	}
	return nil
}

func CtxSetVersionInfo(r *http.Request, v *apidef.VersionInfo) {
	if v == nil {
		panic("setting a nil context VersionData")
	}
	setCtxValue(r, VersionData, v)
}

func CtxGetVersionKey(r *http.Request) string {
	if v := r.Context().Value(VersionKeyContext); v != nil {
		return v.(string)
	}
	return ""
}

func CtxSetVersionKey(r *http.Request, k string) {
	if k == "" {
		panic("setting a nil context VersionKeyContext")
	}
	setCtxValue(r, VersionKeyContext, k)
}
