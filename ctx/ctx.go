package ctx

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"

	logger "github.com/TykTechnologies/tyk/log"
)

type Key uint

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
	SelfLooping
)

func ctxSetSession(r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey bool) {
	if s == nil {
		panic("setting a nil context SessionData")
	}

	if s.KeyID == "" {
		s.KeyID = GetAuthToken(r)
	}

	if s.KeyHashEmpty() {
		s.SetKeyHash(storage.HashKey(s.KeyID, hashKey))
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, SessionData, s)

	ctx = context.WithValue(ctx, AuthToken, s.KeyID)

	if scheduleUpdate {
		s.Touch()
	}

	httputil.SetContext(r, ctx)
}

func GetAuthToken(r *http.Request) string {
	if v := r.Context().Value(AuthToken); v != nil {
		value, ok := v.(string)
		if ok {
			return value
		}
	}
	return ""
}

func GetSession(r *http.Request) *user.SessionState {
	if v := r.Context().Value(SessionData); v != nil {
		if val, ok := v.(*user.SessionState); ok {
			return val
		} else {
			logger.Get().Warning("SessionState struct differ from the gateway version, trying to unmarshal.")
			sess := user.SessionState{}
			b, _ := json.Marshal(v)
			e := json.Unmarshal(b, &sess)
			if e == nil {
				return &sess
			}
		}
	}
	return nil
}

func SetSession(r *http.Request, s *user.SessionState, scheduleUpdate bool, hashKey ...bool) {
	if len(hashKey) > 1 {
		ctxSetSession(r, s, scheduleUpdate, hashKey[0])
	} else {
		ctxSetSession(r, s, scheduleUpdate, config.Global().HashKeys)
	}
}

// SetDefinition sets an API definition object to the request context.
func SetDefinition(r *http.Request, s *apidef.APIDefinition) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, Definition, s)
	httputil.SetContext(r, ctx)
}

// GetDefinition will return a deep copy of the API definition valid for the request.
func GetDefinition(r *http.Request) *apidef.APIDefinition {
	if v := r.Context().Value(Definition); v != nil {
		if val, ok := v.(*apidef.APIDefinition); ok {
			return reflect.Clone(val)
		}
	}

	return nil
}

// SetOASDefinition sets an OAS API definition object to the request context.
func SetOASDefinition(r *http.Request, s *oas.OAS) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, OASDefinition, s)
	httputil.SetContext(r, ctx)
}

// GetOASDefinition will return a deep copy of the OAS API definition valid for the request.
func GetOASDefinition(r *http.Request) *oas.OAS {
	if v := r.Context().Value(OASDefinition); v != nil {
		if val, ok := v.(*oas.OAS); ok {
			return reflect.Clone(val)
		}
	}

	return nil
}
