package oas

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuth2_HasContentRecognisesTokenExchange(t *testing.T) {
	o := &OAuth2{TokenExchange: &OAuth2TokenExchange{Enabled: true}}
	assert.True(t, o.HasContent())

	o = &OAuth2{}
	assert.False(t, o.HasContent())
}

func TestOAuth2TokenExchange_RoundTripPreservesAllFields(t *testing.T) {
	te := &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{
				Name:          "primary",
				Issuers:       []string{"https://idp.example.com", "https://idp-realm-2.example.com"},
				TokenEndpoint: "https://idp.example.com/oauth/token",
				ClientAuth: &OAuth2ClientAuth{
					Method:       OAuth2ClientAuthBasic,
					ClientID:     "tyk-gateway",
					ClientSecret: "vault://kv/tyk/exchange",
				},
				DefaultTarget: &OAuth2DefaultTarget{
					Audience: "https://upstream.example.com",
					Scopes:   []string{"read:billing", "write:billing"},
				},
				CustomParams: map[string]string{"requested_issuer": "broker"},
			},
		},
	}

	b, err := json.Marshal(te)
	require.NoError(t, err)

	var out OAuth2TokenExchange
	require.NoError(t, json.Unmarshal(b, &out))

	require.Len(t, out.Providers, 1)
	p := out.Providers[0]
	assert.Equal(t, "primary", p.Name)
	assert.Equal(t, []string{"https://idp.example.com", "https://idp-realm-2.example.com"}, p.Issuers)
	assert.Equal(t, "https://idp.example.com/oauth/token", p.TokenEndpoint)
	require.NotNil(t, p.ClientAuth)
	assert.Equal(t, OAuth2ClientAuthBasic, p.ClientAuth.Method)
	assert.Equal(t, "tyk-gateway", p.ClientAuth.ClientID)
	assert.Equal(t, "vault://kv/tyk/exchange", p.ClientAuth.ClientSecret)
	require.NotNil(t, p.DefaultTarget)
	assert.Equal(t, "https://upstream.example.com", p.DefaultTarget.Audience)
	assert.Equal(t, []string{"read:billing", "write:billing"}, p.DefaultTarget.Scopes)
	assert.Equal(t, "broker", p.CustomParams["requested_issuer"])
}

func TestOAuth2TokenExchange_OmitEmpty(t *testing.T) {
	te := &OAuth2TokenExchange{}
	b, err := json.Marshal(te)
	require.NoError(t, err)
	// `enabled` is always emitted (master toggle), but providers must not appear.
	assert.JSONEq(t, `{"enabled":false}`, string(b))
}

func TestOAuth2TokenExchange_TwoProvidersPreserveOrder(t *testing.T) {
	te := &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "primary", Issuers: []string{"https://primary"}, TokenEndpoint: "https://primary/token", ClientAuth: &OAuth2ClientAuth{ClientID: "p"}},
			{Name: "alt", Issuers: []string{"https://alt"}, TokenEndpoint: "https://alt/token", ClientAuth: &OAuth2ClientAuth{ClientID: "a"}},
		},
	}
	b, err := json.Marshal(te)
	require.NoError(t, err)

	var out OAuth2TokenExchange
	require.NoError(t, json.Unmarshal(b, &out))

	require.Len(t, out.Providers, 2)
	assert.Equal(t, "primary", out.Providers[0].Name)
	assert.Equal(t, "alt", out.Providers[1].Name)
}

func TestOperation_RoundTripJSONPreservesExchange(t *testing.T) {
	enabled := true
	op := &Operation{Exchange: &OAuth2Exchange{
		Enabled:  &enabled,
		Audience: "https://upstream",
		Scopes:   []string{"users:read"},
	}}
	b, err := json.Marshal(op)
	require.NoError(t, err)

	var out Operation
	require.NoError(t, json.Unmarshal(b, &out))

	require.NotNil(t, out.Exchange)
	require.NotNil(t, out.Exchange.Enabled)
	assert.True(t, *out.Exchange.Enabled)
	assert.Equal(t, "https://upstream", out.Exchange.Audience)
	assert.Equal(t, []string{"users:read"}, out.Exchange.Scopes)
}

func TestOAuth2Exchange_IsActive(t *testing.T) {
	cases := []struct {
		name string
		ex   *OAuth2Exchange
		want bool
	}{
		{"nil", nil, false},
		{"absent enabled is inactive", &OAuth2Exchange{}, false},
		{"explicit true", &OAuth2Exchange{Enabled: boolPtr(true)}, true},
		{"explicit false", &OAuth2Exchange{Enabled: boolPtr(false)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ex.IsActive())
		})
	}
}

func TestOAuth2Exchange_InfersScopesFromSecurity(t *testing.T) {
	cases := []struct {
		name string
		ex   *OAuth2Exchange
		want bool
	}{
		{"nil block", nil, false},
		{"enabled absent — inference off", &OAuth2Exchange{}, false},
		{"explicit true + empty scopes — infer", &OAuth2Exchange{Enabled: boolPtr(true)}, true},
		{"explicit true + non-empty scopes — no infer", &OAuth2Exchange{Enabled: boolPtr(true), Scopes: []string{"x"}}, false},
		{"explicit false — no infer regardless of scopes", &OAuth2Exchange{Enabled: boolPtr(false)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ex.InfersScopesFromSecurity())
		})
	}
}

func TestValidateOAuth2Schemes_DisabledExchange_NoCheck(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: false,
		// Empty providers would be invalid if Enabled=true; with
		// Enabled=false the block is inert and must not error.
	})
	assert.NoError(t, s.ValidateOAuth2Schemes())
}

func TestValidateOAuth2Schemes_EnabledWithoutProviders(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{Enabled: true})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "providers[] is empty")
}

func TestValidateOAuth2Schemes_EmptyProviderName(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{TokenEndpoint: "https://idp/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
		},
	})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "providers[0].name is required")
}

func TestValidateOAuth2Schemes_DuplicateProviderName(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "p", Issuers: []string{"https://a"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "ca"}},
			{Name: "p", Issuers: []string{"https://b"}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "cb"}},
		},
	})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate tokenExchange.provider name "p"`)
}

func TestValidateOAuth2Schemes_OverlappingIssuers(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "p1", Issuers: []string{"https://shared"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "ca"}},
			{Name: "p2", Issuers: []string{"https://shared"}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "cb"}},
		},
	})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate issuer "https://shared"`)
	assert.Contains(t, err.Error(), `"p1"`)
	assert.Contains(t, err.Error(), `"p2"`)
}

func TestValidateOAuth2Schemes_EmptyTokenEndpoint(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "p", Issuers: []string{"https://a"}, ClientAuth: &OAuth2ClientAuth{ClientID: "ca"}},
		},
	})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `empty tokenEndpoint`)
}

func TestValidateOAuth2Schemes_EmptyClientId(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "p", Issuers: []string{"https://a"}, TokenEndpoint: "https://a/token"},
		},
	})
	err := s.ValidateOAuth2Schemes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty clientAuth.clientId")
}

func TestValidateOAuth2Schemes_RejectsReservedCustomParams(t *testing.T) {
	reserved := []string{
		OAuth2FormGrantType, OAuth2FormSubjectToken, OAuth2FormSubjectTokenType,
		OAuth2FormRequestedTokenType, OAuth2FormAudience, OAuth2FormResource,
		OAuth2FormScope, OAuth2FormActorToken, OAuth2FormActorTokenType,
		OAuth2FormClientID, OAuth2FormClientSecret,
		OAuth2FormClientAssertion, OAuth2FormClientAssertionType,
	}
	for _, key := range reserved {
		t.Run(key, func(t *testing.T) {
			s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
				Enabled: true,
				Providers: []OAuth2TokenExchangeProvider{
					{
						Name:          "p",
						Issuers:       []string{"https://a"},
						TokenEndpoint: "https://a/token",
						ClientAuth:    &OAuth2ClientAuth{ClientID: "ca"},
						CustomParams:  map[string]string{key: "x"},
					},
				},
			})
			err := s.ValidateOAuth2Schemes()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "customParams cannot override reserved")
			assert.Contains(t, err.Error(), key)
		})
	}
}

func TestValidateOAuth2Schemes_HappyMultiProvider(t *testing.T) {
	s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
		Enabled: true,
		Providers: []OAuth2TokenExchangeProvider{
			{Name: "primary", Issuers: []string{"https://idp-1"}, TokenEndpoint: "https://idp-1/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c1"}, CustomParams: map[string]string{"requested_issuer": "broker"}},
			{Name: "alt", Issuers: []string{"https://idp-2", "https://idp-2-canonical"}, TokenEndpoint: "https://idp-2/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c2"}},
		},
	})
	assert.NoError(t, s.ValidateOAuth2Schemes())
}

func TestOAuth2_RawMapWithTokenExchangePromotesToTypedScheme(t *testing.T) {
	raw := map[string]interface{}{
		"tokenExchange": map[string]interface{}{
			"enabled": true,
			"providers": []interface{}{
				map[string]interface{}{
					"name":          "primary",
					"issuers":       []interface{}{"https://idp"},
					"tokenEndpoint": "https://idp/token",
					"clientAuth":    map[string]interface{}{"clientId": "tyk-gateway"},
				},
			},
		},
	}
	o := asOAuth2Scheme(raw)
	require.NotNil(t, o)
	require.NotNil(t, o.TokenExchange)
	assert.True(t, o.TokenExchange.Enabled)
	require.Len(t, o.TokenExchange.Providers, 1)
	assert.Equal(t, "primary", o.TokenExchange.Providers[0].Name)
}

// newOAuth2WithTokenExchange builds a minimal OAS with the new oauth2
// scheme carrying just the given tokenExchange block.
func newOAuth2WithTokenExchange(name string, te *OAuth2TokenExchange) *OAS {
	s := newOAuth2Fixture(name)
	o := s.GetTykOAuth2Config(name)
	require := func() *OAuth2 {
		if o != nil {
			return o
		}
		return &OAuth2{}
	}
	got := require()
	got.TokenExchange = te
	// Stuff back into the tyk-extension via the same getter so the
	// validation walk sees it.
	tykAuth := s.getTykAuthentication()
	tykAuth.SecuritySchemes[name] = got
	return s
}

// TestOAS_Validate_TokenExchange and TestOAS_ValidateForMCP_TokenExchange pin
// that token-exchange validation errors surface through the top-level
// OAS.Validate and OAS.ValidateForMCP chains respectively — not only when
// ValidateOAuth2Schemes is called directly. They would fail if the
// ValidateOAuth2Schemes() call was removed from either chain.
func TestOAS_Validate_TokenExchange(t *testing.T) {
	validProvider := OAuth2TokenExchangeProvider{
		Name:          "primary",
		Issuers:       []string{"https://idp.example.com"},
		TokenEndpoint: "https://idp.example.com/token",
		ClientAuth:    &OAuth2ClientAuth{ClientID: "tyk-gw"},
	}

	tests := []struct {
		name      string
		te        *OAuth2TokenExchange
		wantErr   string
	}{
		{
			name:    "valid single provider passes",
			te:      &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{validProvider}},
			wantErr: "",
		},
		{
			name:    "disabled block with no providers passes",
			te:      &OAuth2TokenExchange{Enabled: false},
			wantErr: "",
		},
		{
			name:    "enabled with no providers is rejected",
			te:      &OAuth2TokenExchange{Enabled: true},
			wantErr: "providers[] is empty",
		},
		{
			name: "duplicate provider name is rejected",
			te: &OAuth2TokenExchange{
				Enabled: true,
				Providers: []OAuth2TokenExchangeProvider{
					{Name: "dup", Issuers: []string{"https://a"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
					{Name: "dup", Issuers: []string{"https://b"}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
				},
			},
			wantErr: `duplicate tokenExchange.provider name "dup"`,
		},
		{
			name: "overlapping issuers across providers is rejected",
			te: &OAuth2TokenExchange{
				Enabled: true,
				Providers: []OAuth2TokenExchangeProvider{
					{Name: "a", Issuers: []string{"https://shared"}, TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
					{Name: "b", Issuers: []string{"https://shared"}, TokenEndpoint: "https://b/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
				},
			},
			wantErr: "duplicate issuer",
		},
		{
			name: "reserved customParams key is rejected",
			te: &OAuth2TokenExchange{
				Enabled: true,
				Providers: []OAuth2TokenExchangeProvider{
					{Name: "p", TokenEndpoint: "https://a/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"},
						CustomParams: map[string]string{OAuth2FormGrantType: "bad"}},
				},
			},
			wantErr: "reserved RFC 8693 wire key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newOAuth2WithTokenExchange("corpOAuth", tt.te)
			err := s.Validate(context.Background())
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestOAS_ValidateForMCP_TokenExchange(t *testing.T) {
	t.Run("misconfigured token exchange is also rejected by ValidateForMCP", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{Enabled: true})
		err := s.ValidateForMCP(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "providers[] is empty")
	})

	t.Run("valid token exchange passes ValidateForMCP", func(t *testing.T) {
		s := newOAuth2WithTokenExchange("corpOAuth", &OAuth2TokenExchange{
			Enabled: true,
			Providers: []OAuth2TokenExchangeProvider{
				{Name: "p", Issuers: []string{"https://idp"}, TokenEndpoint: "https://idp/token", ClientAuth: &OAuth2ClientAuth{ClientID: "c"}},
			},
		})
		assert.NoError(t, s.ValidateForMCP(context.Background()))
	})
}
