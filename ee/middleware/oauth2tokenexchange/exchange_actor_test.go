//go:build ee || dev

package oauth2tokenexchange

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

// formCapturingIdP returns a stub IdP that records the last exchange form body
// and replies with a fixed exchanged token.
func formCapturingIdP(t *testing.T, gotForm *url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"exchanged","expires_in":300}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeAtIdP_SendsActorTokenWireShape(t *testing.T) {
	var gotForm url.Values
	srv := formCapturingIdP(t, &gotForm)
	m := newTestMiddleware()
	provider := &oas.OAuth2TokenExchangeProvider{TokenEndpoint: srv.URL}
	target := &oauth2common.Target{Audience: "api.acme.internal"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	t.Run("with actor token sends actor_token + access_token type", func(t *testing.T) {
		tok, _, err := m.exchangeAtIdP(ctx, provider, "subject-tok", "actor-tok", target)
		require.NoError(t, err)
		assert.Equal(t, "exchanged", tok)
		assert.Equal(t, "actor-tok", gotForm.Get(oas.OAuth2FormActorToken))
		assert.Equal(t, oas.OAuth2TokenTypeAccessToken, gotForm.Get(oas.OAuth2FormActorTokenType),
			"default actor_token_type must be access_token for PingAM/PingOne compatibility")
		assert.Equal(t, oas.OAuth2TokenTypeAccessToken, gotForm.Get(oas.OAuth2FormSubjectTokenType),
			"subject_token_type is always access_token")
	})

	t.Run("impersonation omits actor fields", func(t *testing.T) {
		_, _, err := m.exchangeAtIdP(ctx, provider, "subject-tok", "", target)
		require.NoError(t, err)
		assert.Empty(t, gotForm.Get(oas.OAuth2FormActorToken))
		assert.Empty(t, gotForm.Get(oas.OAuth2FormActorTokenType))
	})
}

func TestExchangeAtIdP_ActorTokenTypeJWTOverride(t *testing.T) {
	var gotForm url.Values
	srv := formCapturingIdP(t, &gotForm)
	m := newTestMiddleware()
	provider := &oas.OAuth2TokenExchangeProvider{
		TokenEndpoint: srv.URL,
		ActorToken: &oas.OAuth2ActorToken{
			Source:         oas.OAuth2ActorSourceStatic,
			ActorTokenType: oas.OAuth2TokenTypeJWT,
			Static:         &oas.OAuth2ActorStatic{Token: "ignored-here"},
		},
	}
	target := &oauth2common.Target{Audience: "aud"}
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()

	_, _, err := m.exchangeAtIdP(ctx, provider, "subject-tok", "actor-tok", target)
	require.NoError(t, err)
	assert.Equal(t, oas.OAuth2TokenTypeJWT, gotForm.Get(oas.OAuth2FormActorTokenType),
		"actorTokenType override must reach the wire")
	assert.Equal(t, oas.OAuth2TokenTypeAccessToken, gotForm.Get(oas.OAuth2FormSubjectTokenType),
		"overriding actor_token_type must not change subject_token_type")
}

func TestAcquireActorToken_Header_RequiredAbsent_TypedMissingError(t *testing.T) {
	m := newTestMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	provider := &oas.OAuth2TokenExchangeProvider{
		ActorToken: &oas.OAuth2ActorToken{Source: oas.OAuth2ActorSourceHeader},
	}

	_, _, err := m.acquireActorToken(r, provider)
	require.Error(t, err)
	assert.IsType(t, &oauth2common.MissingActorTokenError{}, err,
		"a missing required actor header must be a typed error so it renders as 401 invalid_token")
}
