package oauth2common

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func providerFixture(name, iss, endpoint string, target *oas.OAuth2DefaultTarget) oas.OAuth2TokenExchangeProvider {
	return oas.OAuth2TokenExchangeProvider{
		Name:          name,
		Issuers:       []string{iss},
		TokenEndpoint: endpoint,
		ClientAuth:    &oas.OAuth2ClientAuth{ClientID: "c-" + name},
		DefaultTarget: target,
	}
}

func TestSelectExchangeProvider_MatchByIss(t *testing.T) {
	providers := []oas.OAuth2TokenExchangeProvider{
		providerFixture("primary", "https://idp-a", "https://idp-a/token", nil),
		providerFixture("alt", "https://idp-b", "https://idp-b/token", nil),
	}
	p := SelectExchangeProvider(providers, "https://idp-b")
	require.NotNil(t, p)
	assert.Equal(t, "alt", p.Name)
}

func TestSelectExchangeProvider_NoMatch_ReturnsNil(t *testing.T) {
	providers := []oas.OAuth2TokenExchangeProvider{
		providerFixture("primary", "https://idp-a", "https://idp-a/token", nil),
	}
	assert.Nil(t, SelectExchangeProvider(providers, "https://idp-rogue"))
}

func TestSelectExchangeProvider_EmptyIss_SingleProviderFallback(t *testing.T) {
	providers := []oas.OAuth2TokenExchangeProvider{
		providerFixture("only", "https://idp-a", "https://idp-a/token", nil),
	}
	p := SelectExchangeProvider(providers, "")
	require.NotNil(t, p)
	assert.Equal(t, "only", p.Name)
}

func TestSelectExchangeProvider_EmptyIss_MultiProvider_ReturnsNil(t *testing.T) {
	// Two or more providers and an empty iss must NOT silently pick one
	// — pinning the security guard.
	providers := []oas.OAuth2TokenExchangeProvider{
		providerFixture("primary", "https://idp-a", "https://idp-a/token", nil),
		providerFixture("alt", "https://idp-b", "https://idp-b/token", nil),
	}
	assert.Nil(t, SelectExchangeProvider(providers, ""))
}

func TestSelectExchangeProvider_MultiIssuerOnOneProvider(t *testing.T) {
	p := oas.OAuth2TokenExchangeProvider{
		Name:          "broker",
		Issuers:       []string{"https://realm-a", "https://realm-b", "https://realm-c"},
		TokenEndpoint: "https://idp/token",
		ClientAuth:    &oas.OAuth2ClientAuth{ClientID: "c"},
	}
	providers := []oas.OAuth2TokenExchangeProvider{p}
	match := SelectExchangeProvider(providers, "https://realm-b")
	require.NotNil(t, match)
	assert.Equal(t, "broker", match.Name)
}

func TestMergeTargetForProvider_PerOpAudienceWins(t *testing.T) {
	ex := &oas.OAuth2Exchange{Audience: "https://override", Scopes: []string{"x"}}
	prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "https://default", Scopes: []string{"def"}})
	got := MergeTargetForProvider(ex, &prov, nil)
	require.NotNil(t, got)
	assert.Equal(t, "https://override", got.Audience)
	assert.Equal(t, []string{"x"}, got.Scopes)
}

func TestMergeTargetForProvider_FullOverrideIgnoresDefaults(t *testing.T) {
	ex := &oas.OAuth2Exchange{Audience: "https://override", Scopes: []string{"x"}, Resources: []string{"https://r"}}
	prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "https://default", Scopes: []string{"def"}, Resources: []string{"https://def"}})
	got := MergeTargetForProvider(ex, &prov, []string{"inferred"})
	require.NotNil(t, got)
	assert.Equal(t, &Target{Audience: "https://override", Scopes: []string{"x"}, Resources: []string{"https://r"}}, got)
}

func TestMergeTargetForProvider_DefaultsFallback(t *testing.T) {
	ex := &oas.OAuth2Exchange{}
	prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "https://default", Scopes: []string{"def"}})
	got := MergeTargetForProvider(ex, &prov, nil)
	require.NotNil(t, got)
	assert.Equal(t, "https://default", got.Audience)
	assert.Equal(t, []string{"def"}, got.Scopes)
}

func TestMergeTargetForProvider_InferredScopesFromSecurity(t *testing.T) {
	enabled := true
	ex := &oas.OAuth2Exchange{Enabled: &enabled}
	prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "https://default", Scopes: []string{"fallback"}})
	got := MergeTargetForProvider(ex, &prov, []string{"inferred:scope"})
	require.NotNil(t, got)
	assert.Equal(t, "https://default", got.Audience)
	assert.Equal(t, []string{"inferred:scope"}, got.Scopes, "inferred scopes should pre-empt provider defaults")
}

func TestMergeTargetForProvider_InferredScopesIgnoredWhenEnabledNil(t *testing.T) {
	ex := &oas.OAuth2Exchange{}
	prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "https://default", Scopes: []string{"fallback"}})
	got := MergeTargetForProvider(ex, &prov, []string{"inferred:scope"})
	require.NotNil(t, got)
	assert.Equal(t, []string{"fallback"}, got.Scopes, "inferred scopes require explicit Enabled=true on the exchange block")
}

func TestMergeTargetForProvider_NilWhenNoAudienceResolvable(t *testing.T) {
	ex := &oas.OAuth2Exchange{Scopes: []string{"x"}}
	prov := providerFixture("p", "https://idp", "https://idp/token", nil)
	got := MergeTargetForProvider(ex, &prov, nil)
	assert.Nil(t, got, "no audience anywhere = no target")
}

func TestState_RoundTripsThroughRequestContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	state := &State{
		Claims:               jwt.MapClaims{"iss": "https://idp"},
		RawToken:             "abc.def.ghi",
		APIID:                "api-1",
		MatchedOperationID:   "getMail",
		MatchedPrimitiveName: "search",
		MatchedPrimitiveType: "tool",
		InferredScopes:       []string{"users:read"},
	}
	SetState(r, state)

	got := GetState(r)
	require.NotNil(t, got)
	assert.Equal(t, "abc.def.ghi", got.RawToken)
	assert.Equal(t, "api-1", got.APIID)
	assert.Equal(t, "getMail", got.MatchedOperationID)
	assert.Equal(t, "search", got.MatchedPrimitiveName)
	assert.Equal(t, "tool", got.MatchedPrimitiveType)
	assert.Equal(t, []string{"users:read"}, got.InferredScopes)
	assert.Equal(t, "https://idp", got.Claims["iss"])
}

func TestState_GetStateNilWhenAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, GetState(r))
}

func TestExchangeDoneFlag(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.False(t, IsExchangeDone(r))
	MarkExchangeDone(r)
	assert.True(t, IsExchangeDone(r))
}

func TestNoMatchingProviderError_Message(t *testing.T) {
	e := &NoMatchingProviderError{Iss: "https://idp"}
	assert.Contains(t, e.Error(), "https://idp")
	missing := &NoMatchingProviderError{}
	assert.Contains(t, missing.Error(), "missing iss")
}

func TestExchangeFailedError_Message(t *testing.T) {
	e := &ExchangeFailedError{Status: 400, IdpError: "invalid_grant", Description: "user not found"}
	assert.Contains(t, e.Error(), "invalid_grant")
	assert.Contains(t, e.Error(), "user not found")

	noDesc := &ExchangeFailedError{Status: 500, IdpError: "server_error"}
	assert.Contains(t, noDesc.Error(), "server_error")
	assert.Contains(t, noDesc.Error(), "500")
}

func TestExchangeFailedError_ErrorsIs(t *testing.T) {
	e := &ExchangeFailedError{Status: 500}
	var target *ExchangeFailedError
	assert.True(t, errors.As(e, &target))
}

func TestDecodeIdPError_StandardJSON(t *testing.T) {
	idpErr, desc := DecodeIdPError([]byte(`{"error":"invalid_grant","error_description":"user not found"}`))
	assert.Equal(t, "invalid_grant", idpErr)
	assert.Equal(t, "user not found", desc)
}

func TestDecodeIdPError_NonJSONFallbackTruncates(t *testing.T) {
	body := make([]byte, MaxIdPErrorBodyBytes+50)
	for i := range body {
		body[i] = 'a'
	}
	idpErr, desc := DecodeIdPError(body)
	assert.Equal(t, "unknown", idpErr)
	assert.Less(t, len(desc), len(body)+1, "expected truncation")
	assert.Contains(t, desc, "...(truncated)")
}

func TestNewIdPHTTPClient_HonoursTimeout(t *testing.T) {
	client := NewIdPHTTPClient(7)
	assert.Equal(t, 7, int(client.Timeout))
	assert.NotNil(t, client.Transport)
}

func TestMergeTargetForProvider_Resources(t *testing.T) {
	enabled := true
	defaults := &oas.OAuth2DefaultTarget{Audience: "abc123", Resources: []string{"https://default"}}
	tests := []struct {
		name      string
		ex        *oas.OAuth2Exchange
		grantType string
		defaults  *oas.OAuth2DefaultTarget
		want      []string
	}{
		{name: "provider default applies with no override", defaults: defaults, want: []string{"https://default"}},
		{name: "operation list wins over the default", ex: &oas.OAuth2Exchange{Enabled: &enabled, Resources: []string{"https://op-a", "https://op-b"}}, defaults: defaults, want: []string{"https://op-a", "https://op-b"}},
		{name: "empty operation list falls back to the default", ex: &oas.OAuth2Exchange{Enabled: &enabled, Audience: "other"}, defaults: defaults, want: []string{"https://default"}},
		{name: "MCP primitive override wins over the default", ex: (&oas.MCPPrimitive{Operation: oas.Operation{Exchange: &oas.OAuth2Exchange{Enabled: &enabled, Resources: []string{"https://tool"}}}}).Exchange, defaults: defaults, want: []string{"https://tool"}},
		{name: "nothing configured stays nil", defaults: &oas.OAuth2DefaultTarget{Audience: "abc123"}},
		{name: "jwt-bearer clears an override list", ex: &oas.OAuth2Exchange{Enabled: &enabled, Resources: []string{"https://op"}}, grantType: oas.OAuth2ProviderGrantJWTBearer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prov := providerFixture("p", "https://idp", "https://idp/token", tc.defaults)
			prov.GrantType = tc.grantType
			got := MergeTargetForProvider(tc.ex, &prov, nil)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Resources)
		})
	}

	t.Run("merge copies, never aliases, the configured list", func(t *testing.T) {
		prov := providerFixture("p", "https://idp", "https://idp/token", &oas.OAuth2DefaultTarget{Audience: "abc123", Resources: []string{"https://default"}})
		got := MergeTargetForProvider(nil, &prov, nil)
		got.Resources[0] = "mutated"
		assert.Equal(t, "https://default", prov.DefaultTarget.Resources[0])
	})
}
