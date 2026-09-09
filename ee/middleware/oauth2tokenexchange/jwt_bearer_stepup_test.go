//go:build ee || dev

package oauth2tokenexchange

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// errorIdP returns a stub IdP that replies with the given status and raw body.
func errorIdP(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The claims value carries bytes ("c1>x?!") whose base64 contains + / and
// forces = padding, so the StdEncoding assertions below actually pin
// StdEncoding — base64url (RawURLEncoding/URLEncoding) would differ and fail.
const stepUpClaims = `{"access_token":{"acrs":{"essential":true,"value":"c1>x?!"}}}`

const stepUpChallengeBody = `{"error":"interaction_required","error_description":"AADSTS50076 ...","claims":"{\"access_token\":{\"acrs\":{\"essential\":true,\"value\":\"c1>x?!\"}}}","authorization_uri":"https://idp.example.com/authorize"}`

func stepUpTestProvider(tokenEndpoint string) *oas.OAuth2TokenExchangeProvider {
	return &oas.OAuth2TokenExchangeProvider{
		Name:          "corp-idp",
		GrantType:     oas.OAuth2ProviderGrantJWTBearer,
		TokenEndpoint: tokenEndpoint,
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "app-id", ClientSecret: "app-secret"},
	}
}

// TestExchangeAtIdP_JWTBearer_StepUpChallenge pins that an interaction_required
// response under the jwt-bearer grant becomes a typed StepUpRequiredError
// carrying the raw claims challenge and authorization_uri — not a generic
// exchange failure.
func TestExchangeAtIdP_JWTBearer_StepUpChallenge(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, stepUpChallengeBody)
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := mwWithoutTykOps().exchangeAtIdP(ctx, stepUpTestProvider(srv.URL), "user-assertion", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	require.ErrorAs(t, err, &stepUp, "interaction_required must classify as step-up")
	assert.Contains(t, stepUp.Claims, "acrs", "the raw claims challenge must be carried")
	assert.Equal(t, "https://idp.example.com/authorize", stepUp.AuthorizationURI)
}

// TestExchangeAtIdP_JWTBearer_DetectionKeysOnErrorCode pins that detection keys
// on the error code, not the HTTP status: a generic rejection with the same
// status follows the normal failure path.
func TestExchangeAtIdP_JWTBearer_DetectionKeysOnErrorCode(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"expired"}`)
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := mwWithoutTykOps().exchangeAtIdP(ctx, stepUpTestProvider(srv.URL), "user-assertion", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	assert.NotErrorAs(t, err, &stepUp, "invalid_grant must not be step-up")
	var failed *oauth2common.ExchangeFailedError
	assert.ErrorAs(t, err, &failed)
}

// TestExchangeAtIdP_TokenExchange_InteractionRequiredIsIdPError pins that the
// relay is scoped to the jwt-bearer grant: an RFC 8693 provider seeing the same
// interaction_required body follows today's rejection path unchanged.
func TestExchangeAtIdP_TokenExchange_InteractionRequiredIsIdPError(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, stepUpChallengeBody)
	target := &oauth2common.Target{Audience: "aud"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	provider := &oas.OAuth2TokenExchangeProvider{TokenEndpoint: srv.URL}
	_, _, err := mwWithoutTykOps().exchangeAtIdP(ctx, provider, "subject", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	assert.NotErrorAs(t, err, &stepUp, "the relay must be scoped to the jwt-bearer grant")
	var failed *oauth2common.ExchangeFailedError
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "interaction_required", failed.IdpError)
}

// TestWriteStepUpRequiredResponse pins the front-channel challenge: a 401 with
// a Bearer insufficient_claims challenge carrying the base64 (padded, not
// base64url) claims and the authorization_uri.
func TestWriteStepUpRequiredResponse(t *testing.T) {
	t.Run("full challenge", func(t *testing.T) {
		m := mwWithoutTykOps()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		m.writeStepUpRequiredResponse(w, r, &oauth2common.StepUpRequiredError{
			Claims:           stepUpClaims,
			AuthorizationURI: "https://idp.example.com/authorize",
		})

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		challenge := w.Header().Get(header.WWWAuthenticate)
		assert.Contains(t, challenge, `error="insufficient_claims"`)
		assert.Contains(t, challenge, `claims="`+base64.StdEncoding.EncodeToString([]byte(stepUpClaims))+`"`)
		assert.Contains(t, challenge, `authorization_uri="https://idp.example.com/authorize"`)
	})

	t.Run("absent fields are omitted, not sent empty", func(t *testing.T) {
		m := mwWithoutTykOps()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		m.writeStepUpRequiredResponse(w, r, &oauth2common.StepUpRequiredError{})

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		challenge := w.Header().Get(header.WWWAuthenticate)
		assert.Contains(t, challenge, `error="insufficient_claims"`)
		assert.NotContains(t, challenge, "claims=")
		assert.NotContains(t, challenge, "authorization_uri=")
	})
}
