//go:build ee || dev

package oauth2tokenexchange

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oauth2common"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// mwWithoutTykOps builds a Middleware whose OAS carries no x-tyk middleware, so
// per-primitive / per-operation resolution is skipped and resolution falls
// through to the provider's defaultTarget.
func mwWithoutTykOps() *Middleware {
	return &Middleware{Spec: model.MergedAPI{OAS: &oas.OAS{}}}
}

func TestParseExchangeResponse(t *testing.T) {
	t.Run("token with expires_in", func(t *testing.T) {
		tok, ttl, err := parseExchangeResponse([]byte(`{"access_token":"abc","expires_in":300}`))
		require.NoError(t, err)
		assert.Equal(t, "abc", tok)
		assert.Equal(t, 300*time.Second, ttl)
	})

	t.Run("token without expires_in yields zero lifetime", func(t *testing.T) {
		tok, ttl, err := parseExchangeResponse([]byte(`{"access_token":"abc"}`))
		require.NoError(t, err)
		assert.Equal(t, "abc", tok)
		assert.Equal(t, time.Duration(0), ttl)
	})

	t.Run("non-positive expires_in yields zero lifetime", func(t *testing.T) {
		_, ttl, err := parseExchangeResponse([]byte(`{"access_token":"abc","expires_in":-5}`))
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), ttl)
	})

	t.Run("missing access_token is an error", func(t *testing.T) {
		_, _, err := parseExchangeResponse([]byte(`{"expires_in":300}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing access_token")
	})

	t.Run("invalid JSON is an error", func(t *testing.T) {
		_, _, err := parseExchangeResponse([]byte(`not-json`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding exchange response")
	})
}

func TestBuildExchangeForm(t *testing.T) {
	provider := &oas.OAuth2TokenExchangeProvider{
		CustomParams: map[string]string{"requested_issuer": "broker"},
		ClientAuth:   &oas.OAuth2ClientAuth{ClientID: "cid", ClientSecret: "secret"},
	}
	target := &oauth2common.Target{Audience: "https://upstream", Scopes: []string{"read", "write"}}

	t.Run("sets RFC 8693 grant + subject token fields", func(t *testing.T) {
		form := buildExchangeForm(provider, "subject-token", "", target, oas.OAuth2ClientAuthBasic)
		assert.Equal(t, oas.OAuth2GrantTypeTokenExchange, form.Get(oas.OAuth2FormGrantType))
		assert.Equal(t, "subject-token", form.Get(oas.OAuth2FormSubjectToken))
		assert.Equal(t, oas.OAuth2TokenTypeAccessToken, form.Get(oas.OAuth2FormSubjectTokenType))
	})

	t.Run("audience populates both audience and resource", func(t *testing.T) {
		form := buildExchangeForm(provider, "s", "", target, oas.OAuth2ClientAuthBasic)
		assert.Equal(t, "https://upstream", form.Get(oas.OAuth2FormAudience))
		assert.Equal(t, "https://upstream", form.Get(oas.OAuth2FormResource))
	})

	t.Run("scopes are space-joined and customParams included", func(t *testing.T) {
		form := buildExchangeForm(provider, "s", "", target, oas.OAuth2ClientAuthBasic)
		assert.Equal(t, "read write", form.Get(oas.OAuth2FormScope))
		assert.Equal(t, "broker", form.Get("requested_issuer"))
	})

	t.Run("client_secret_post injects credentials into the form", func(t *testing.T) {
		form := buildExchangeForm(provider, "s", "", target, oas.OAuth2ClientAuthPost)
		assert.Equal(t, "cid", form.Get(oas.OAuth2FormClientID))
		assert.Equal(t, "secret", form.Get(oas.OAuth2FormClientSecret))
	})

	t.Run("basic auth keeps credentials out of the form", func(t *testing.T) {
		form := buildExchangeForm(provider, "s", "", target, oas.OAuth2ClientAuthBasic)
		assert.Empty(t, form.Get(oas.OAuth2FormClientID))
		assert.Empty(t, form.Get(oas.OAuth2FormClientSecret))
	})

	t.Run("empty audience and scopes omit those fields", func(t *testing.T) {
		form := buildExchangeForm(provider, "s", "", &oauth2common.Target{}, oas.OAuth2ClientAuthBasic)
		assert.Empty(t, form.Get(oas.OAuth2FormAudience))
		assert.Empty(t, form.Get(oas.OAuth2FormScope))
	})
}

func TestApplyClientAuth(t *testing.T) {
	newReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://idp/token", nil)
	}

	t.Run("client_secret_post sets no Authorization header", func(t *testing.T) {
		req := newReq()
		provider := &oas.OAuth2TokenExchangeProvider{ClientAuth: &oas.OAuth2ClientAuth{ClientID: "cid", ClientSecret: "s"}}
		require.NoError(t, applyClientAuth(req, provider, oas.OAuth2ClientAuthPost))
		_, _, ok := req.BasicAuth()
		assert.False(t, ok, "post method must not set basic auth")
	})

	t.Run("basic method sets basic auth header", func(t *testing.T) {
		req := newReq()
		provider := &oas.OAuth2TokenExchangeProvider{ClientAuth: &oas.OAuth2ClientAuth{ClientID: "cid", ClientSecret: "secret"}}
		require.NoError(t, applyClientAuth(req, provider, oas.OAuth2ClientAuthBasic))
		user, pass, ok := req.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "cid", user)
		assert.Equal(t, "secret", pass)
	})

	t.Run("empty method defaults to basic", func(t *testing.T) {
		req := newReq()
		provider := &oas.OAuth2TokenExchangeProvider{ClientAuth: &oas.OAuth2ClientAuth{ClientID: "cid", ClientSecret: "secret"}}
		require.NoError(t, applyClientAuth(req, provider, ""))
		_, _, ok := req.BasicAuth()
		assert.True(t, ok)
	})

	t.Run("nil clientAuth is a no-op, not an error", func(t *testing.T) {
		req := newReq()
		require.NoError(t, applyClientAuth(req, &oas.OAuth2TokenExchangeProvider{}, ""))
		_, _, ok := req.BasicAuth()
		assert.False(t, ok)
	})

	t.Run("private_key_jwt sets no Authorization header (assertion is in the form)", func(t *testing.T) {
		req := newReq()
		provider := &oas.OAuth2TokenExchangeProvider{ClientAuth: &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthPrivateKeyJWT, ClientID: "cid", CertID: "c1"}}
		require.NoError(t, applyClientAuth(req, provider, oas.OAuth2ClientAuthPrivateKeyJWT))
		_, _, ok := req.BasicAuth()
		assert.False(t, ok, "private_key_jwt must not set basic auth")
	})

	t.Run("unsupported method is rejected", func(t *testing.T) {
		req := newReq()
		provider := &oas.OAuth2TokenExchangeProvider{ClientAuth: &oas.OAuth2ClientAuth{ClientID: "cid"}}
		err := applyClientAuth(req, provider, "mutual_tls")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported clientAuth.method")
	})
}

func TestInboundRemaining(t *testing.T) {
	t.Run("missing exp claim yields zero", func(t *testing.T) {
		assert.Equal(t, time.Duration(0), inboundRemaining(&oauth2common.State{Claims: jwt.MapClaims{}}))
	})

	t.Run("non-numeric exp yields zero", func(t *testing.T) {
		st := &oauth2common.State{Claims: jwt.MapClaims{oas.OAuth2ClaimExp: "not-a-number"}}
		assert.Equal(t, time.Duration(0), inboundRemaining(st))
	})

	t.Run("expired token yields zero", func(t *testing.T) {
		st := &oauth2common.State{Claims: jwt.MapClaims{oas.OAuth2ClaimExp: float64(time.Now().Add(-time.Hour).Unix())}}
		assert.Equal(t, time.Duration(0), inboundRemaining(st))
	})

	t.Run("future exp (float64) yields positive remaining", func(t *testing.T) {
		st := &oauth2common.State{Claims: jwt.MapClaims{oas.OAuth2ClaimExp: float64(time.Now().Add(time.Hour).Unix())}}
		got := inboundRemaining(st)
		assert.Greater(t, got, 50*time.Minute)
		assert.LessOrEqual(t, got, time.Hour)
	})

	t.Run("future exp (int64) yields positive remaining", func(t *testing.T) {
		st := &oauth2common.State{Claims: jwt.MapClaims{oas.OAuth2ClaimExp: time.Now().Add(time.Hour).Unix()}}
		assert.Greater(t, inboundRemaining(st), 50*time.Minute)
	})
}

func TestCacheTTL(t *testing.T) {
	t.Run("derived mode bounds by the smallest of expiresIn/inboundRemaining/maxTimeout minus margin", func(t *testing.T) {
		cache := &oas.OAuth2ExchangeCache{Mode: oas.OAuth2CacheModeDerived}
		// expiresIn 10m, inboundRemaining 8m → bound by 8m, default 30s margin.
		got := cacheTTL(cache, 10*time.Minute, 8*time.Minute)
		assert.Equal(t, 8*time.Minute-oauth2common.DefaultSafetyMargin, got)
	})

	t.Run("static mode uses configured timeout minus margin", func(t *testing.T) {
		cache := &oas.OAuth2ExchangeCache{
			Mode:    oas.OAuth2CacheModeStatic,
			Timeout: tyktime.ReadableDuration(5 * time.Minute),
		}
		got := cacheTTL(cache, 0, 0)
		assert.Equal(t, 5*time.Minute-oauth2common.DefaultSafetyMargin, got)
	})

	t.Run("empty mode defaults to derived", func(t *testing.T) {
		cache := &oas.OAuth2ExchangeCache{}
		got := cacheTTL(cache, 10*time.Minute, 0)
		assert.Equal(t, 10*time.Minute-oauth2common.DefaultSafetyMargin, got)
	})
}

func TestExchangeAtIdP(t *testing.T) {
	target := &oauth2common.Target{Audience: "https://upstream", Scopes: []string{"read"}}

	t.Run("successful exchange returns token and lifetime", func(t *testing.T) {
		var gotForm struct {
			grantType, subjectToken, audience, scope string
			basicOK                                  bool
		}
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotForm.grantType = r.PostForm.Get(oas.OAuth2FormGrantType)
			gotForm.subjectToken = r.PostForm.Get(oas.OAuth2FormSubjectToken)
			gotForm.audience = r.PostForm.Get(oas.OAuth2FormAudience)
			gotForm.scope = r.PostForm.Get(oas.OAuth2FormScope)
			_, _, gotForm.basicOK = r.BasicAuth()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "exchanged", "expires_in": 120})
		}))
		defer idp.Close()

		provider := &oas.OAuth2TokenExchangeProvider{
			Name:          "p",
			TokenEndpoint: idp.URL,
			ClientAuth:    &oas.OAuth2ClientAuth{Method: oas.OAuth2ClientAuthBasic, ClientID: "cid", ClientSecret: "secret"},
		}

		tok, ttl, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound-token", "", target)
		require.NoError(t, err)
		assert.Equal(t, "exchanged", tok)
		assert.Equal(t, 120*time.Second, ttl)
		assert.Equal(t, oas.OAuth2GrantTypeTokenExchange, gotForm.grantType)
		assert.Equal(t, "inbound-token", gotForm.subjectToken)
		assert.Equal(t, "https://upstream", gotForm.audience)
		assert.Equal(t, "read", gotForm.scope)
		assert.True(t, gotForm.basicOK, "basic credentials must reach the IdP")
	})

	t.Run("non-2xx maps to ExchangeFailedError carrying the status", func(t *testing.T) {
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}))
		defer idp.Close()

		provider := &oas.OAuth2TokenExchangeProvider{Name: "p", TokenEndpoint: idp.URL}
		_, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), provider, "inbound", "", target)
		require.Error(t, err)
		var failed *oauth2common.ExchangeFailedError
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, http.StatusUnauthorized, failed.Status)
		assert.Equal(t, "invalid_client", failed.IdpError)
	})

	t.Run("empty tokenEndpoint is rejected before any call", func(t *testing.T) {
		_, _, err := mwWithoutTykOps().exchangeAtIdP(context.Background(), &oas.OAuth2TokenExchangeProvider{Name: "p"}, "inbound", "", target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tokenEndpoint is empty")
	})
}

func TestResolveExchangeTarget_ProviderDefault(t *testing.T) {
	m := mwWithoutTykOps()
	st := &oauth2common.State{}

	t.Run("falls back to provider defaultTarget", func(t *testing.T) {
		provider := &oas.OAuth2TokenExchangeProvider{
			DefaultTarget: &oas.OAuth2DefaultTarget{Audience: "https://api", Scopes: []string{"read", "write"}},
		}
		got := m.resolveExchangeTarget(st, provider)
		require.NotNil(t, got)
		assert.Equal(t, "https://api", got.Audience)
		assert.Equal(t, []string{"read", "write"}, got.Scopes)
	})

	t.Run("nil when no primitive/operation match and no provider default", func(t *testing.T) {
		assert.Nil(t, m.resolveExchangeTarget(st, &oas.OAuth2TokenExchangeProvider{}))
	})

	t.Run("nil when provider default audience is empty", func(t *testing.T) {
		provider := &oas.OAuth2TokenExchangeProvider{DefaultTarget: &oas.OAuth2DefaultTarget{Scopes: []string{"read"}}}
		assert.Nil(t, m.resolveExchangeTarget(st, provider))
	})
}

func TestExchangeWouldFire_ProviderDefault(t *testing.T) {
	m := mwWithoutTykOps()
	st := &oauth2common.State{}

	t.Run("true when a provider declares a default audience", func(t *testing.T) {
		cfg := &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
			Providers: []oas.OAuth2TokenExchangeProvider{
				{Name: "p", DefaultTarget: &oas.OAuth2DefaultTarget{Audience: "https://api"}},
			},
		}}
		assert.True(t, m.exchangeWouldFire(st, cfg))
	})

	t.Run("false when no provider has a default audience and nothing matched", func(t *testing.T) {
		cfg := &oas.OAuth2{TokenExchange: &oas.OAuth2TokenExchange{
			Providers: []oas.OAuth2TokenExchangeProvider{{Name: "p"}},
		}}
		assert.False(t, m.exchangeWouldFire(st, cfg))
	})
}
