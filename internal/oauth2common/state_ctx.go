package oauth2common

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// State carries the context set by OSS OAuth2Middleware for the EE exchange.
type State struct {
	// Claims is the JWT-parsed claim set on the inbound token.
	Claims jwt.MapClaims

	// ReplaceVariables applies the gateway's standard request-context
	// variable replacement to a config string; nil means pass-through.
	ReplaceVariables func(in string) string

	// RawToken is the inbound Bearer (after stripping the prefix).
	RawToken string

	// OASConfig is the resolved OAS-side oauth2 block.
	OASConfig *oas.OAuth2

	// APIID is the matched API definition ID.
	APIID string

	// MatchedOperationID is the OAS operationId for the request, if any.
	MatchedOperationID string

	// MatchedPrimitiveName is the MCP primitive name the request resolved to, if any.
	MatchedPrimitiveName string

	// MatchedPrimitiveType is the MCP primitive type ("tool", "resource", "prompt").
	// Required alongside MatchedPrimitiveName to avoid collision when tool and prompt
	// share the same name.
	MatchedPrimitiveType string

	// InferredScopes is the flattened union of OR-of-AND scope alternatives for the request.
	InferredScopes []string
}

type stateCtxKey struct{}

// SetState attaches s to the request's context.
// Mutates *r in-place (shared-pointer chain contract); cloning r mid-chain breaks the handoff.
func SetState(r *http.Request, s *State) {
	ctx := context.WithValue(r.Context(), stateCtxKey{}, s)
	*r = *r.WithContext(ctx)
}

// GetState returns the request's State or nil when none was set.
func GetState(r *http.Request) *State {
	v, ok := r.Context().Value(stateCtxKey{}).(*State)
	if !ok {
		return nil
	}
	return v
}

type exchangeDoneCtxKey struct{}

// MarkExchangeDone prevents re-running the exchange for MCP fan-out sub-requests.
func MarkExchangeDone(r *http.Request) {
	ctx := context.WithValue(r.Context(), exchangeDoneCtxKey{}, true)
	*r = *r.WithContext(ctx)
}

func IsExchangeDone(r *http.Request) bool {
	v, ok := r.Context().Value(exchangeDoneCtxKey{}).(bool)
	if !ok {
		return false
	}
	return v
}
