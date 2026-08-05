//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
)

func jwtBearerTestProvider(customParams map[string]string) *oas.OAuth2TokenExchangeProvider {
	return &oas.OAuth2TokenExchangeProvider{
		Name:         "corp-idp",
		GrantType:    oas.OAuth2ProviderGrantJWTBearer,
		ClientAuth:   &oas.OAuth2ClientAuth{ClientID: "cid", ClientSecret: "secret"},
		CustomParams: customParams,
	}
}

func TestBuildExchangeForm_JWTBearer(t *testing.T) {
	target := &oauth2common.Target{Audience: "api://orders-api", Scopes: []string{"Orders.Read"}}

	t.Run("sends the jwt-bearer grant with the inbound token as assertion", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "user-token", target, oas.OAuth2ClientAuthPost)
		assert.Equal(t, oas.OAuth2GrantTypeJWTBearer, form.Get(oas.OAuth2FormGrantType))
		assert.Equal(t, "user-token", form.Get(oas.OAuth2FormAssertion))
	})

	t.Run("renders the target into scope and emits no audience or resource", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", target, oas.OAuth2ClientAuthPost)
		assert.Equal(t, "api://orders-api/Orders.Read", form.Get(oas.OAuth2FormScope))
		_, hasAudience := form[oas.OAuth2FormAudience]
		_, hasResource := form[oas.OAuth2FormResource]
		assert.False(t, hasAudience, "jwt-bearer must not emit an audience wire parameter")
		assert.False(t, hasResource, "jwt-bearer must not emit a resource wire parameter")
	})

	t.Run("emits no RFC 8693 subject token fields", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", target, oas.OAuth2ClientAuthPost)
		_, hasSubjectToken := form[oas.OAuth2FormSubjectToken]
		_, hasSubjectTokenType := form[oas.OAuth2FormSubjectTokenType]
		assert.False(t, hasSubjectToken)
		assert.False(t, hasSubjectTokenType)
	})

	t.Run("audience with no scopes renders no scope parameter at all", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", &oauth2common.Target{Audience: "api://orders-api"}, oas.OAuth2ClientAuthPost)
		_, hasScope := form[oas.OAuth2FormScope]
		assert.False(t, hasScope, "the gateway never invents a scope")
	})

	t.Run("customParams pass through, including a literal audience form field", func(t *testing.T) {
		provider := jwtBearerTestProvider(map[string]string{
			"requested_token_use":  "on_behalf_of",
			oas.OAuth2FormAudience: "https://idp-specific",
		})
		form := buildExchangeForm(provider, "s", target, oas.OAuth2ClientAuthPost)
		assert.Equal(t, "on_behalf_of", form.Get("requested_token_use"))
		assert.Equal(t, "https://idp-specific", form.Get(oas.OAuth2FormAudience))
	})

	t.Run("bare provider sends no vendor parameters of its own", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", target, oas.OAuth2ClientAuthPost)
		_, hasRequestedTokenUse := form["requested_token_use"]
		assert.False(t, hasRequestedTokenUse, "the gateway never adds vendor flags on its own")
	})

	t.Run("client_secret_post injects credentials into the form", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", target, oas.OAuth2ClientAuthPost)
		assert.Equal(t, "cid", form.Get(oas.OAuth2FormClientID))
		assert.Equal(t, "secret", form.Get(oas.OAuth2FormClientSecret))
	})

	t.Run("basic auth keeps credentials out of the form", func(t *testing.T) {
		form := buildExchangeForm(jwtBearerTestProvider(nil), "s", target, oas.OAuth2ClientAuthBasic)
		assert.Empty(t, form.Get(oas.OAuth2FormClientID))
		assert.Empty(t, form.Get(oas.OAuth2FormClientSecret))
	})
}

// TestExchangeAtIdP_JWTBearer pins the wire shape end-to-end against a
// recording IdP, alongside the RFC 8693 shape from the same logical target.
func TestExchangeAtIdP_JWTBearer(t *testing.T) {
	target := &oauth2common.Target{Audience: "api://orders-api", Scopes: []string{"Orders.Read"}}

	t.Run("successful jwt-bearer exchange", func(t *testing.T) {
		var got struct {
			grantType, assertion, scope, requestedTokenUse string
			subjectTokenPresent, audiencePresent           bool
			basicOK                                        bool
		}
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			got.grantType = r.PostForm.Get(oas.OAuth2FormGrantType)
			got.assertion = r.PostForm.Get(oas.OAuth2FormAssertion)
			got.scope = r.PostForm.Get(oas.OAuth2FormScope)
			got.requestedTokenUse = r.PostForm.Get("requested_token_use")
			_, got.subjectTokenPresent = r.PostForm[oas.OAuth2FormSubjectToken]
			_, got.audiencePresent = r.PostForm[oas.OAuth2FormAudience]
			_, _, got.basicOK = r.BasicAuth()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "downstream-token", "expires_in": 120})
		}))
		defer idp.Close()

		provider := jwtBearerTestProvider(map[string]string{"requested_token_use": "on_behalf_of"})
		provider.TokenEndpoint = idp.URL
		provider.ClientAuth.Method = oas.OAuth2ClientAuthPost

		tok, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound-user-token", target)
		require.NoError(t, err)
		assert.Equal(t, "downstream-token", tok)
		assert.Equal(t, oas.OAuth2GrantTypeJWTBearer, got.grantType)
		assert.Equal(t, "inbound-user-token", got.assertion)
		assert.Equal(t, "api://orders-api/Orders.Read", got.scope)
		assert.Equal(t, "on_behalf_of", got.requestedTokenUse)
		assert.False(t, got.subjectTokenPresent)
		assert.False(t, got.audiencePresent)
		assert.False(t, got.basicOK, "client_secret_post must not set a basic auth header")
	})

	t.Run("IdP rejection maps to ExchangeFailedError with the IdP code relayed", func(t *testing.T) {
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"AADSTS70011: scope grammar violated"}`))
		}))
		defer idp.Close()

		provider := jwtBearerTestProvider(nil)
		provider.TokenEndpoint = idp.URL

		_, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound", target)
		var failed *oauth2common.ExchangeFailedError
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, "invalid_grant", failed.IdpError)
		assert.Contains(t, failed.Description, "AADSTS70011")
	})
}
