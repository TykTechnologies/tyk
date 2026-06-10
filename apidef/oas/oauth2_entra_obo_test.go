package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// teProvider builds a minimal valid provider, overlaid by the mutator.
func teProvider(mut func(*OAuth2TokenExchangeProvider)) *OAuth2TokenExchange {
	p := OAuth2TokenExchangeProvider{
		Name:          "p",
		Issuers:       []string{"https://login.microsoftonline.com/tid/v2.0"},
		TokenEndpoint: "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
		ClientAuth:    &OAuth2ClientAuth{Method: OAuth2ClientAuthPost, ClientID: "app", ClientSecret: "s"},
		DefaultTarget: &OAuth2DefaultTarget{Audience: "api://orders", Scopes: []string{"Orders.Read"}},
	}
	if mut != nil {
		mut(&p)
	}
	return &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{p}}
}

// TestOAuth2Provider_Flow_RoundTrip pins that the flow discriminator survives
// a JSON round-trip and is omitted when absent (so existing RFC 8693 providers
// serialise unchanged).
func TestOAuth2Provider_Flow_RoundTrip(t *testing.T) {
	withFlow := teProvider(func(p *OAuth2TokenExchangeProvider) { p.Flow = OAuth2FlowOnBehalfOf })
	b, err := json.Marshal(withFlow)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"flow":"on-behalf-of"`)

	var out OAuth2TokenExchange
	require.NoError(t, json.Unmarshal(b, &out))
	assert.Equal(t, OAuth2FlowOnBehalfOf, out.Providers[0].Flow)

	noFlow, err := json.Marshal(OAuth2TokenExchangeProvider{Name: "p"})
	require.NoError(t, err)
	assert.NotContains(t, string(noFlow), "flow")
}

// TestOAuth2Provider_IsOnBehalfOf pins the discriminator helper: only the explicit
// on-behalf-of value is Entra; empty (default) and token-exchange are not.
func TestOAuth2Provider_IsOnBehalfOf(t *testing.T) {
	assert.False(t, (&OAuth2TokenExchangeProvider{}).IsOnBehalfOf(), "empty flow defaults to token-exchange")
	assert.False(t, (&OAuth2TokenExchangeProvider{Flow: OAuth2FlowTokenExchange}).IsOnBehalfOf())
	assert.True(t, (&OAuth2TokenExchangeProvider{Flow: OAuth2FlowOnBehalfOf}).IsOnBehalfOf())
}

// TestEntraScopeString pins the audience+scopes → Entra `scope` translation:
// discrete scopes are resource-prefixed, an audience with no scopes becomes
// "<audience>/.default", and an already-qualified scope is taken verbatim
// (the explicit-scope escape hatch).
func TestEntraScopeString(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		scopes   []string
		want     string
	}{
		{"audience plus discrete scopes are resource-prefixed", "api://orders", []string{"Orders.Read", "Orders.Write"}, "api://orders/Orders.Read api://orders/Orders.Write"},
		{"audience alone becomes .default", "api://orders", nil, "api://orders/.default"},
		{"already-qualified scope is verbatim (escape hatch)", "api://orders", []string{"https://graph.microsoft.com/User.Read"}, "https://graph.microsoft.com/User.Read"},
		{"explicit .default scope passes through", "api://orders", []string{"api://orders/.default"}, "api://orders/.default"},
		{"no audience, no scopes yields empty", "", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, EntraScopeString(tt.audience, tt.scopes))
		})
	}
}

// TestValidateOAuth2Schemes_Flow pins that the flow enum is validated at
// API-load: empty and the two known values pass, anything else is rejected.
func TestValidateOAuth2Schemes_Flow(t *testing.T) {
	for _, f := range []string{"", OAuth2FlowTokenExchange, OAuth2FlowOnBehalfOf} {
		s := newOAuth2WithTokenExchange("corpOAuth", teProvider(func(p *OAuth2TokenExchangeProvider) { p.Flow = f }))
		assert.NoError(t, s.ValidateOAuth2Schemes(), "flow %q should be accepted", f)
	}

	s := newOAuth2WithTokenExchange("corpOAuth", teProvider(func(p *OAuth2TokenExchangeProvider) { p.Flow = "saml-bearer" }))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flow")
	assert.Contains(t, err.Error(), OAuth2FlowOnBehalfOf)
}

func entra(mut func(*OAuth2TokenExchangeProvider)) *OAuth2TokenExchange {
	return teProvider(func(p *OAuth2TokenExchangeProvider) {
		p.Flow = OAuth2FlowOnBehalfOf
		if mut != nil {
			mut(p)
		}
	})
}

// TestValidateOAuth2Schemes_EntraOBO_Happy pins that a well-formed Entra OBO
// provider (secret login, single-resource default target) validates clean.
func TestValidateOAuth2Schemes_EntraOBO_Happy(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", entra(nil))
	assert.NoError(t, s.ValidateOAuth2Schemes())
}

// TestValidateOAuth2Schemes_EntraOBO_RejectsActorToken pins that an actorToken
// block is rejected under on-behalf-of — OBO is single-token delegation.
func TestValidateOAuth2Schemes_EntraOBO_RejectsActorToken(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", entra(func(p *OAuth2TokenExchangeProvider) {
		p.ActorToken = &OAuth2ActorToken{Source: OAuth2ActorSourceHeader}
	}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actorToken is not valid")
	assert.Contains(t, err.Error(), OAuth2FlowOnBehalfOf)
}

// TestValidateOAuth2Schemes_EntraOBO_RequiresTarget pins that an empty default
// target (no audience, no scopes) is rejected — Entra cannot infer the target.
func TestValidateOAuth2Schemes_EntraOBO_RequiresTarget(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", entra(func(p *OAuth2TokenExchangeProvider) {
		p.DefaultTarget = &OAuth2DefaultTarget{}
	}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

// TestValidateOAuth2Schemes_EntraOBO_RejectsDefaultMixing pins the .default
// mixing rule (Entra AADSTS70011): .default cannot ride with discrete scopes.
func TestValidateOAuth2Schemes_EntraOBO_RejectsDefaultMixing(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", entra(func(p *OAuth2TokenExchangeProvider) {
		p.DefaultTarget = &OAuth2DefaultTarget{Audience: "api://orders", Scopes: []string{"Orders.Read", ".default"}}
	}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".default")
}

// TestValidateOAuth2Schemes_EntraOBO_RejectsMultiResource pins the single-resource
// rule: one OBO exchange targets one resource.
func TestValidateOAuth2Schemes_EntraOBO_RejectsMultiResource(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", entra(func(p *OAuth2TokenExchangeProvider) {
		p.DefaultTarget = &OAuth2DefaultTarget{Scopes: []string{"api://orders/Read", "api://billing/Read"}}
	}))
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single resource")
}

// TestValidateOAuth2Schemes_EntraOBO_ReservedParams pins that the OBO-owned wire
// keys (assertion, requested_token_use) cannot be set via customParams.
func TestValidateOAuth2Schemes_EntraOBO_ReservedParams(t *testing.T) {
	for _, key := range []string{OAuth2FormAssertion, OAuth2FormRequestedTokenUse} {
		s := newOAuth2WithTokenExchange("corpOAuth", entra(func(p *OAuth2TokenExchangeProvider) {
			p.CustomParams = map[string]string{key: "x"}
		}))
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err, "customParams key %q must be reserved", key)
		assert.Contains(t, err.Error(), key)
	}
}
