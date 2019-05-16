package main

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

// Enums for keys to be stored in a session context - this is how gorilla expects
// these to be implemented and is lifted pretty much from docs
const (
	SessionData = iota
	UpdateSession
	AuthToken
	HashedAuthToken
	VersionData
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
	RequestLogger
)

// TODO: Don't modify http.Request values in-place. We must right now
// because our middleware design doesn't pass around http.Request
// pointers, so we have no way to modify the pointer in a middleware.
//
// If we ever redesign middlewares - or if we find another workaround -
// revisit this.
func setContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}
func setCtxValue(r *http.Request, key, val interface{}) {
	setContext(r, context.WithValue(r.Context(), key, val))
}

func ctxGetData(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(ContextData); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

func ctxSetData(r *http.Request, m map[string]interface{}) {
	if m == nil {
		panic("setting a nil context ContextData")
	}
	setCtxValue(r, ContextData, m)
}

func ctxGetSession(r *http.Request) *user.SessionState {
	if v := r.Context().Value(SessionData); v != nil {
		return v.(*user.SessionState)
	}
	return nil
}

func ctxSetSession(r *http.Request, s *user.SessionState, token string, scheduleUpdate bool) {
	if s == nil {
		panic("setting a nil context SessionData")
	}

	if token == "" {
		token = ctxGetAuthToken(r)
	}

	if s.KeyHashEmpty() {
		s.SetKeyHash(storage.HashKey(token))
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, SessionData, s)
	ctx = context.WithValue(ctx, AuthToken, token)

	if scheduleUpdate {
		ctx = context.WithValue(ctx, UpdateSession, true)
	}

	setContext(r, ctx)
}

func ctxScheduleSessionUpdate(r *http.Request) {
	setCtxValue(r, UpdateSession, true)
}

func ctxDisableSessionUpdate(r *http.Request) {
	setCtxValue(r, UpdateSession, false)
}

func ctxSessionUpdateScheduled(r *http.Request) bool {
	if v := r.Context().Value(UpdateSession); v != nil {
		return v.(bool)
	}
	return false
}

func ctxGetAuthToken(r *http.Request) string {
	if v := r.Context().Value(AuthToken); v != nil {
		return v.(string)
	}
	return ""
}

func ctxGetTrackedPath(r *http.Request) string {
	if v := r.Context().Value(TrackThisEndpoint); v != nil {
		return v.(string)
	}
	return ""
}

func ctxSetTrackedPath(r *http.Request, p string) {
	if p == "" {
		panic("setting a nil context TrackThisEndpoint")
	}
	setCtxValue(r, TrackThisEndpoint, p)
}

func ctxGetDoNotTrack(r *http.Request) bool {
	return r.Context().Value(DoNotTrackThisEndpoint) == true
}

func ctxSetDoNotTrack(r *http.Request, b bool) {
	setCtxValue(r, DoNotTrackThisEndpoint, b)
}

func ctxGetVersionInfo(r *http.Request) *apidef.VersionInfo {
	if v := r.Context().Value(VersionData); v != nil {
		return v.(*apidef.VersionInfo)
	}
	return nil
}

func ctxSetVersionInfo(r *http.Request, v *apidef.VersionInfo) {
	setCtxValue(r, VersionData, v)
}

func ctxSetOrigRequestURL(r *http.Request, url *url.URL) {
	setCtxValue(r, OrigRequestURL, url)
}

func ctxGetOrigRequestURL(r *http.Request) *url.URL {
	if v := r.Context().Value(OrigRequestURL); v != nil {
		if urlVal, ok := v.(*url.URL); ok {
			return urlVal
		}
	}

	return nil
}

func ctxSetUrlRewritePath(r *http.Request, path string) {
	setCtxValue(r, UrlRewritePath, path)
}

func ctxGetUrlRewritePath(r *http.Request) string {
	if v := r.Context().Value(UrlRewritePath); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return ""
}

func ctxSetCheckLoopLimits(r *http.Request, b bool) {
	setCtxValue(r, CheckLoopLimits, b)
}

// Should we check Rate limits and Quotas?
func ctxCheckLimits(r *http.Request) bool {
	// If looping disabled, allow all
	if !ctxLoopingEnabled(r) {
		return true
	}

	if v := r.Context().Value(CheckLoopLimits); v != nil {
		return v.(bool)
	}

	return false
}

func ctxSetRequestMethod(r *http.Request, path string) {
	setCtxValue(r, RequestMethod, path)
}

func ctxGetRequestMethod(r *http.Request) string {
	if v := r.Context().Value(RequestMethod); v != nil {
		if strVal, ok := v.(string); ok {
			return strVal
		}
	}
	return r.Method
}

func ctxGetDefaultVersion(r *http.Request) bool {
	return r.Context().Value(VersionDefault) != nil
}

func ctxSetDefaultVersion(r *http.Request) {
	setCtxValue(r, VersionDefault, true)
}

func ctxLoopingEnabled(r *http.Request) bool {
	return ctxLoopLevel(r) > 0
}

func ctxLoopLevel(r *http.Request) int {
	if v := r.Context().Value(LoopLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLevel(r *http.Request, value int) {
	setCtxValue(r, LoopLevel, value)
}

func ctxIncLoopLevel(r *http.Request, loopLimit int) {
	ctxSetLoopLimit(r, loopLimit)
	ctxSetLoopLevel(r, ctxLoopLevel(r)+1)
}

func ctxLoopLevelLimit(r *http.Request) int {
	if v := r.Context().Value(LoopLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetLoopLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxLoopLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, LoopLevelLimit, limit)
	}
}

func ctxThrottleLevelLimit(r *http.Request) int {
	if v := r.Context().Value(ThrottleLevelLimit); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxThrottleLevel(r *http.Request) int {
	if v := r.Context().Value(ThrottleLevel); v != nil {
		if intVal, ok := v.(int); ok {
			return intVal
		}
	}

	return 0
}

func ctxSetThrottleLimit(r *http.Request, limit int) {
	// Can be set only one time per request
	if ctxThrottleLevelLimit(r) == 0 && limit > 0 {
		setCtxValue(r, ThrottleLevelLimit, limit)
	}
}

func ctxSetThrottleLevel(r *http.Request, value int) {
	setCtxValue(r, ThrottleLevel, value)
}

func ctxIncThrottleLevel(r *http.Request, throttleLimit int) {
	ctxSetThrottleLimit(r, throttleLimit)
	ctxSetThrottleLevel(r, ctxThrottleLevel(r)+1)
}

func ctxTraceEnabled(r *http.Request) bool {
	return r.Context().Value(Trace) != nil
}

func ctxSetTrace(r *http.Request) {
	setCtxValue(r, Trace, true)
}

func ctxGetLogger(r *http.Request) *logrus.Entry {
	if v := r.Context().Value(RequestLogger); v != nil {
		return v.(*logrus.Entry)
	}
	return logrus.NewEntry(log)
}

func ctxSetLogger(r *http.Request, l *logrus.Entry) {
	setCtxValue(r, RequestLogger, l)
}
