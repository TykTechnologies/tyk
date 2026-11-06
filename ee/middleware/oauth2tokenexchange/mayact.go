//go:build ee || dev

package oauth2tokenexchange

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// mayActActorToken returns the actor-token value the may_act check needs to
// resolve the actor identity WITHOUT touching the IdP: empty for the
// client_credentials source (checkMayAct uses the configured clientId), the
// request header value for header, the configured token for static. This lets
// the may_act pre-flight run before the (possibly IdP-touching) acquisition.
func (m *Middleware) mayActActorToken(r *http.Request, at *oas.OAuth2ActorToken) string {
	if at == nil {
		return ""
	}
	switch at.Source {
	case oas.OAuth2ActorSourceHeader:
		hdr, _, _ := actorHeaderSettings(at.Header)
		return r.Header.Get(hdr)
	case oas.OAuth2ActorSourceStatic:
		if at.Static != nil {
			return at.Static.Token
		}
	}
	return ""
}

// checkMayAct enforces RFC 8693 §4.4 may_act when actorToken.requireMayAct is
// true. It verifies the inbound subject token authorizes the configured actor
// BEFORE the IdP call, returning an ActorNotAuthorizedError (rendered as 403)
// on failure. A no-op when requireMayAct is unset/false or no actor is configured.
//
// The IdP remains the authoritative enforcement point — this is defence in
// depth that turns an opaque IdP rejection into a clear gateway error. It only
// fires when the operator opts in, because under central-policy delegation
// (e.g. PingFederate TEPP) the subject token may legitimately carry no may_act.
func (m *Middleware) checkMayAct(claims jwt.MapClaims, at *oas.OAuth2ActorToken, actorToken string) error {
	if at == nil || at.RequireMayAct == nil || !*at.RequireMayAct {
		return nil
	}
	expected := expectedActorID(at, actorToken)

	raw, ok := claims[oas.OAuth2ClaimMayAct]
	if !ok {
		return &oauth2common.ActorNotAuthorizedError{
			Reason: "subject token has no may_act claim; configured actor is not authorized to act on its behalf",
		}
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return &oauth2common.ActorNotAuthorizedError{Reason: "subject token may_act claim is malformed"}
	}
	if expected == "" {
		// Actor identity couldn't be determined (e.g. an opaque header/static
		// actor token). Presence of may_act is the most we can assert.
		return nil
	}
	for _, key := range []string{oas.OAuth2ClaimSub, oas.OAuth2ClaimClientID} {
		if v, _ := obj[key].(string); v != "" && v == expected {
			return nil
		}
	}
	return &oauth2common.ActorNotAuthorizedError{
		Reason: fmt.Sprintf("subject token may_act does not authorize actor %q", expected),
	}
}

// expectedActorID resolves the identity the may_act claim must name. For the
// client_credentials source it's the actor's client_id (what PingFederate /
// PingAM record). For header/static it's the `sub` of the presented actor JWT,
// decoded without signature verification — the IdP verifies it on the exchange.
// Returns "" when the token isn't a parseable JWT (e.g. opaque).
func expectedActorID(at *oas.OAuth2ActorToken, actorToken string) string {
	if at.Source == oas.OAuth2ActorSourceClientCredentials && at.ClientCredentials != nil {
		return at.ClientCredentials.ClientID
	}
	claims, err := oauth2common.ParseUnverifiedClaims(actorToken)
	if err != nil {
		return ""
	}
	return oauth2common.StringClaim(claims, oas.OAuth2ClaimSub)
}
