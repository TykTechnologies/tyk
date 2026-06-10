//go:build ee || dev

package oauth2tokenexchange

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// errorIdP returns a stub IdP that replies with the given status and raw body.
func errorIdP(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const entraClaimsChallenge = `{"error":"interaction_required","error_description":"AADSTS50076 ...","claims":"{\"access_token\":{\"acrs\":{\"essential\":true,\"value\":\"c1\"}}}"}`

// TestExchangeAtIdP_EntraOBO_StepUpChallenge pins that an Entra
// interaction_required response becomes a typed StepUpRequiredError carrying the
// raw claims challenge — not a generic exchange failure.
func TestExchangeAtIdP_EntraOBO_StepUpChallenge(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, entraClaimsChallenge)
	m := newTestMiddleware()
	provider := entraOBOProvider(srv.URL)
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "user-assertion", "", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	require.ErrorAs(t, err, &stepUp, "interaction_required must classify as step-up")
	assert.Contains(t, stepUp.Claims, "acrs", "the raw claims challenge must be carried")
}

// TestExchangeAtIdP_EntraOBO_GenericErrorNotStepUp pins that an ordinary Entra
// rejection (invalid_grant) is a normal exchange failure, not a step-up.
func TestExchangeAtIdP_EntraOBO_GenericErrorNotStepUp(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, `{"error":"invalid_grant","error_description":"expired"}`)
	m := newTestMiddleware()
	provider := entraOBOProvider(srv.URL)
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "user-assertion", "", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	assert.NotErrorAs(t, err, &stepUp, "invalid_grant must not be step-up")
	var fe *oauth2common.ExchangeFailedError
	assert.ErrorAs(t, err, &fe, "invalid_grant must be a normal exchange failure")
}

// TestExchangeAtIdP_RFC8693_InteractionRequiredIsExchangeFailed pins that the
// step-up branch is Entra-only: an RFC 8693 provider seeing interaction_required
// follows the normal failure path.
func TestExchangeAtIdP_RFC8693_InteractionRequiredIsExchangeFailed(t *testing.T) {
	srv := errorIdP(t, http.StatusBadRequest, entraClaimsChallenge)
	m := newTestMiddleware()
	provider := &oas.OAuth2TokenExchangeProvider{TokenEndpoint: srv.URL}
	target := &oauth2common.Target{Audience: "aud"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "subject", "", target)
	require.Error(t, err)
	var stepUp *oauth2common.StepUpRequiredError
	assert.NotErrorAs(t, err, &stepUp, "step-up detection must be scoped to the Entra flavour")
}

// TestParseExchangeResponse_IgnoresExtExpiresIn is a regression guard: Entra's
// ext_expires_in (an outage-resilience window) must not drive the cache TTL —
// only expires_in does.
func TestParseExchangeResponse_IgnoresExtExpiresIn(t *testing.T) {
	_, ttl, err := parseExchangeResponse([]byte(`{"access_token":"x","expires_in":60,"ext_expires_in":3600}`))
	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, ttl, "ext_expires_in must not extend the cache TTL")
}

// TestWriteStepUpRequiredResponse pins the front-channel claims challenge: a 401
// with a Bearer insufficient_claims challenge carrying the base64 (padded) claims
// and the authorization_uri.
func TestWriteStepUpRequiredResponse(t *testing.T) {
	m := mwWithoutTykOps()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := `{"access_token":{"acrs":{"essential":true,"value":"c1"}}}`

	m.writeStepUpRequiredResponse(w, r, &oauth2common.StepUpRequiredError{
		Claims:           claims,
		AuthorizationURI: "https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	challenge := w.Header().Get(header.WWWAuthenticate)
	assert.Contains(t, challenge, `error="insufficient_claims"`)
	assert.Contains(t, challenge, `claims="`+base64.StdEncoding.EncodeToString([]byte(claims))+`"`)
	assert.Contains(t, challenge, `authorization_uri="https://login.microsoftonline.com/tid/oauth2/v2.0/authorize"`)
}

func entraOBOProvider(tokenEndpoint string) *oas.OAuth2TokenExchangeProvider {
	return &oas.OAuth2TokenExchangeProvider{
		Flow:          oas.OAuth2FlowOnBehalfOf,
		TokenEndpoint: tokenEndpoint,
		ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPost, ClientID: "app-id", ClientSecret: "app-secret"},
	}
}

// TestExchangeAtIdP_EntraOBO_RequestShape pins the On-Behalf-Of wire shape: the
// jwt-bearer grant, the inbound token as `assertion`, the requested_token_use
// flag, the translated scope, and the absence of every RFC 8693-only parameter.
func TestExchangeAtIdP_EntraOBO_RequestShape(t *testing.T) {
	var gotForm url.Values
	srv := formCapturingIdP(t, &gotForm)
	m := newTestMiddleware()
	provider := entraOBOProvider(srv.URL)
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	tok, _, err := m.exchangeAtIdP(ctx, provider, "user-assertion", "", target)
	require.NoError(t, err)
	assert.Equal(t, "exchanged", tok)

	// Present: the OBO parameters.
	assert.Equal(t, oas.OAuth2GrantTypeJWTBearer, gotForm.Get(oas.OAuth2FormGrantType))
	assert.Equal(t, "user-assertion", gotForm.Get(oas.OAuth2FormAssertion))
	assert.Equal(t, oas.OAuth2RequestedTokenUseOBO, gotForm.Get(oas.OAuth2FormRequestedTokenUse))
	assert.Equal(t, "api://orders/Orders.Read", gotForm.Get(oas.OAuth2FormScope))
	assert.Equal(t, "app-id", gotForm.Get(oas.OAuth2FormClientID), "client_secret_post puts client_id in the body")
	assert.Equal(t, "app-secret", gotForm.Get(oas.OAuth2FormClientSecret))

	// Absent: every RFC 8693-only parameter.
	assert.Empty(t, gotForm.Get(oas.OAuth2FormSubjectToken))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormSubjectTokenType))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormActorToken))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormActorTokenType))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormAudience))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormResource))
}

// TestExchangeAtIdP_EntraOBO_DefaultScope pins that an audience with no scopes
// is sent as "<audience>/.default".
func TestExchangeAtIdP_EntraOBO_DefaultScope(t *testing.T) {
	var gotForm url.Values
	srv := formCapturingIdP(t, &gotForm)
	m := newTestMiddleware()
	provider := entraOBOProvider(srv.URL)
	target := &oauth2common.Target{Audience: "api://orders"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "user-assertion", "", target)
	require.NoError(t, err)
	assert.Equal(t, "api://orders/.default", gotForm.Get(oas.OAuth2FormScope))
}

// TestExchangeAtIdP_EntraOBO_BasicAuth pins that client_secret_basic sends the
// gateway credentials in the Authorization header (not the body) under the OBO
// flavour — the secret client-auth path is reused unchanged.
func TestExchangeAtIdP_EntraOBO_BasicAuth(t *testing.T) {
	var gotForm url.Values
	var gotAuthUser, gotAuthPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		gotAuthUser, gotAuthPass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged","expires_in":300}`))
	}))
	t.Cleanup(srv.Close)

	m := newTestMiddleware()
	provider := entraOBOProvider(srv.URL)
	provider.ClientAuth.Method = oas.OAuth2ClientAuthBasic
	target := &oauth2common.Target{Audience: "api://orders", Scopes: []string{"Orders.Read"}}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "user-assertion", "", target)
	require.NoError(t, err)
	assert.Equal(t, "app-id", gotAuthUser)
	assert.Equal(t, "app-secret", gotAuthPass)
	assert.Empty(t, gotForm.Get(oas.OAuth2FormClientSecret), "basic auth must not also put the secret in the body")
}

// TestExchangeAtIdP_RFC8693_UnaffectedByFlavour is the regression guard: a
// provider with no flavour still emits the RFC 8693 token-exchange grant.
func TestExchangeAtIdP_RFC8693_UnaffectedByFlavour(t *testing.T) {
	var gotForm url.Values
	srv := formCapturingIdP(t, &gotForm)
	m := newTestMiddleware()
	provider := &oas.OAuth2TokenExchangeProvider{TokenEndpoint: srv.URL}
	target := &oauth2common.Target{Audience: "api.acme.internal"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "subject-tok", "", target)
	require.NoError(t, err)
	assert.Equal(t, oas.OAuth2GrantTypeTokenExchange, gotForm.Get(oas.OAuth2FormGrantType))
	assert.Equal(t, "subject-tok", gotForm.Get(oas.OAuth2FormSubjectToken))
	assert.Equal(t, "api.acme.internal", gotForm.Get(oas.OAuth2FormAudience))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormAssertion))
	assert.Empty(t, gotForm.Get(oas.OAuth2FormRequestedTokenUse))
}
