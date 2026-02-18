package ctx

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/service/core"
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
	InternalRedirectTarget
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
	OASDefinition
	SelfLooping
	// RequestStartTime holds the time when the request entered the middleware chain
	RequestStartTime
	// ErrorClassification holds structured error information for access logs
	ErrorClassification
	// JsonRPCRouting indicates the request came via JSON-RPC routing (MCP, A2A, etc.)
	JsonRPCRouting
	// JSONRPCRequest stores parsed JSON-RPC request data for protocol routing (MCP, A2A, etc.)
	JSONRPCRequest
	// JSONRPCRoutingState stores the routing state for sequential MCP VEM processing.
	// Used by MCPJSONRPCMiddleware and MCPVEMContinuationMiddleware.
	JSONRPCRoutingState
	// MCPRouting indicates the request came via MCP JSON-RPC routing
	MCPRouting
	// OriginalRequestPath stores the original request path before any middleware modifications
	OriginalRequestPath
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

	core.SetContext(r, ctx)
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
	core.SetContext(r, ctx)
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
	core.SetContext(r, ctx)
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

// SetErrorClassification sets the error classification for the request context.
// This is used to store structured error information for access logs.
func SetErrorClassification(r *http.Request, ec *errors.ErrorClassification) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, ErrorClassification, ec)
	core.SetContext(r, ctx)
}

// GetErrorClassification retrieves the error classification from the request context.
// Returns nil if no error classification has been set.
func GetErrorClassification(r *http.Request) *errors.ErrorClassification {
	if v := r.Context().Value(ErrorClassification); v != nil {
		if val, ok := v.(*errors.ErrorClassification); ok {
			return val
		}
	}
	return nil
}
