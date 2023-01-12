package ctx

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/config"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

type Key uint

const (
	SessionData Key = iota
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

	// CacheOptions holds cache options required for cache writer middleware.
	CacheOptions
)

func setContext(r *http.Request, ctx context.Context) {
	r2 := r.WithContext(ctx)
	*r = *r2
}

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
		ctx = context.WithValue(ctx, UpdateSession, true)
	}

	setContext(r, ctx)
}

func GetAuthToken(r *http.Request) string {
	if v := r.Context().Value(AuthToken); v != nil {
		return v.(string)
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

func SetDefinition(r *http.Request, s *apidef.APIDefinition) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, Definition, s)
	setContext(r, ctx)
}

func GetDefinition(r *http.Request) *apidef.APIDefinition {
	if v := r.Context().Value(Definition); v != nil {
		if val, ok := v.(*apidef.APIDefinition); ok {
			return val
		} else {
			logger.Get().Warning("APIDefinition struct differ from the gateway version, trying to unmarshal.")
			def := apidef.APIDefinition{}
			b, _ := json.Marshal(v)
			e := json.Unmarshal(b, &def)
			if e == nil {
				return &def
			}
		}
	}
	return nil
}
