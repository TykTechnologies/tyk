//go:build ee || dev

package oauth2tokenexchange

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

func ccActor(clientID string, requireMayAct *bool) *oas.OAuth2ActorToken {
	return &oas.OAuth2ActorToken{
		Source:            oas.OAuth2ActorSourceClientCredentials,
		ClientCredentials: &oas.OAuth2ActorClientCredentials{ClientID: clientID},
		RequireMayAct:     requireMayAct,
	}
}

func signedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte("test-secret"))
	require.NoError(t, err)
	return s
}

func TestCheckMayAct_SkippedWhenNotRequired(t *testing.T) {
	m := newTestMiddleware()
	assert.NoError(t, m.checkMayAct(jwt.MapClaims{}, ccActor("gw-actor", nil), ""), "requireMayAct nil skips the check")
	assert.NoError(t, m.checkMayAct(jwt.MapClaims{}, ccActor("gw-actor", boolPtr(false)), ""), "requireMayAct false skips the check")
	assert.NoError(t, m.checkMayAct(jwt.MapClaims{}, nil, ""), "no actor block skips the check")
}

func TestCheckMayAct_CC_SubMatches(t *testing.T) {
	m := newTestMiddleware()
	claims := jwt.MapClaims{
		oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimSub: "tyk-gateway-actor"},
	}
	assert.NoError(t, m.checkMayAct(claims, ccActor("tyk-gateway-actor", boolPtr(true)), ""))
}

func TestCheckMayAct_CC_ClientIDMemberMatches(t *testing.T) {
	m := newTestMiddleware()
	claims := jwt.MapClaims{
		oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimClientID: "tyk-gateway-actor"},
	}
	assert.NoError(t, m.checkMayAct(claims, ccActor("tyk-gateway-actor", boolPtr(true)), ""))
}

func TestCheckMayAct_CC_AbsentClaimRejected(t *testing.T) {
	m := newTestMiddleware()
	err := m.checkMayAct(jwt.MapClaims{}, ccActor("tyk-gateway-actor", boolPtr(true)), "")
	require.Error(t, err)
	assert.IsType(t, &oauth2common.ActorNotAuthorizedError{}, err)
}

func TestCheckMayAct_CC_MismatchRejected(t *testing.T) {
	m := newTestMiddleware()
	claims := jwt.MapClaims{
		oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimSub: "some-other-actor"},
	}
	err := m.checkMayAct(claims, ccActor("tyk-gateway-actor", boolPtr(true)), "")
	require.Error(t, err)
	assert.IsType(t, &oauth2common.ActorNotAuthorizedError{}, err)
}

func TestCheckMayAct_MalformedClaimRejected(t *testing.T) {
	m := newTestMiddleware()
	claims := jwt.MapClaims{oas.OAuth2ClaimMayAct: "not-an-object"}
	err := m.checkMayAct(claims, ccActor("tyk-gateway-actor", boolPtr(true)), "")
	require.Error(t, err)
	assert.IsType(t, &oauth2common.ActorNotAuthorizedError{}, err)
}

func TestCheckMayAct_HeaderSource_DecodesActorTokenSub(t *testing.T) {
	m := newTestMiddleware()
	actorTok := signedJWT(t, jwt.MapClaims{oas.OAuth2ClaimSub: "agent-7"})
	at := &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader, RequireMayAct: boolPtr(true)}

	ok := jwt.MapClaims{oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimSub: "agent-7"}}
	assert.NoError(t, m.checkMayAct(ok, at, actorTok), "may_act naming the actor token's sub authorizes it")

	bad := jwt.MapClaims{oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimSub: "agent-9"}}
	assert.Error(t, m.checkMayAct(bad, at, actorTok))
}

func TestCheckMayAct_OpaqueActorToken_PresenceOnly(t *testing.T) {
	m := newTestMiddleware()
	at := &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader, RequireMayAct: boolPtr(true)}
	// Opaque (non-JWT) actor token: actor id can't be resolved, so presence of
	// may_act is accepted while absence is still rejected.
	present := jwt.MapClaims{oas.OAuth2ClaimMayAct: map[string]interface{}{oas.OAuth2ClaimSub: "whoever"}}
	assert.NoError(t, m.checkMayAct(present, at, "opaque-token"))
	assert.Error(t, m.checkMayAct(jwt.MapClaims{}, at, "opaque-token"))
}

func TestExpectedActorID(t *testing.T) {
	headerActor := &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader}
	// client_credentials uses the configured client id, ignoring the token.
	assert.Equal(t, "gw-actor", expectedActorID(ccActor("gw-actor", boolPtr(true)), ""))
	// header/static decode the actor JWT's sub without verification.
	assert.Equal(t, "alice", expectedActorID(headerActor, signedJWT(t, jwt.MapClaims{oas.OAuth2ClaimSub: "alice"})))
	// opaque / unparseable tokens resolve to no identity.
	assert.Empty(t, expectedActorID(headerActor, "not-a-jwt"))
	assert.Empty(t, expectedActorID(headerActor, ""))
}
