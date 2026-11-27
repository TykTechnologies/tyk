package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exchangeProvider builds a valid provider carrying the given grant and default target.
func exchangeProvider(name, grantType string, target *OAuth2DefaultTarget) OAuth2TokenExchangeProvider {
	return OAuth2TokenExchangeProvider{
		Name:          name,
		GrantType:     grantType,
		Issuers:       []string{"https://idp-" + name + ".example.com"},
		TokenEndpoint: "https://idp.example.com/token",
		ClientAuth:    &OAuth2ClientAuth{ClientID: "cid"},
		DefaultTarget: target,
	}
}

// withMiddleware attaches a Middleware block to an OAS fixture so the
// document-wide audience check can see the per-operation exchange blocks.
func withMiddleware(s *OAS, mw *Middleware) *OAS {
	s.GetTykExtension().Middleware = mw
	return s
}

// activeExchangeOp builds a middleware block with one operation whose exchange
// override is enabled and carries the given audience.
func activeExchangeOp(audience string) *Middleware {
	enabled := true
	return &Middleware{Operations: Operations{
		"getOrders": &Operation{Exchange: &OAuth2Exchange{Enabled: &enabled, Audience: audience, Scopes: []string{"Orders.Read"}}},
	}}
}

// TestValidateOAuth2Schemes_Audience_ProvablyUnresolvable pins rejection of
// the provably broken config: all providers RFC 8693, no audience anywhere.
func TestValidateOAuth2Schemes_Audience_ProvablyUnresolvable(t *testing.T) {
	t.Run("operation exchange with no audience anywhere is rejected", func(t *testing.T) {
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, nil),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audience")
		assert.Contains(t, err.Error(), "getOrders")
	})

	t.Run("the default empty grantType counts as RFC 8693", func(t *testing.T) {
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", "", nil),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		assert.Error(t, s.ValidateOAuth2Schemes())
	})

	t.Run("an MCP primitive exchange with no audience anywhere is rejected", func(t *testing.T) {
		enabled := true
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, nil),
		}}
		mw := &Middleware{McpTools: MCPPrimitives{
			"searchOrders": &MCPPrimitive{Operation: Operation{Exchange: &OAuth2Exchange{Enabled: &enabled}}},
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), mw)
		err := s.ValidateOAuth2Schemes()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "searchOrders")
	})
}

// TestValidateOAuth2Schemes_Audience_AcceptedConfigurations pins shapes that
// load today; rejecting any of them would be a breaking change.
func TestValidateOAuth2Schemes_Audience_AcceptedConfigurations(t *testing.T) {
	rfc8693NoDefault := func() *OAuth2TokenExchange {
		return &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, nil),
		}}
	}

	t.Run("the operation supplies its own audience", func(t *testing.T) {
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", rfc8693NoDefault()), activeExchangeOp("api://orders"))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("no exchange blocks at all — inert config still loads", func(t *testing.T) {
		// The exchange never fires here; the API serves normally today.
		s := newOAuth2WithTokenExchange("corpOAuth", rfc8693NoDefault())
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("the exchange block is disabled — never fires", func(t *testing.T) {
		disabled := false
		mw := &Middleware{Operations: Operations{
			"getOrders": &Operation{Exchange: &OAuth2Exchange{Enabled: &disabled}},
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", rfc8693NoDefault()), mw)
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("a provider supplies a default audience", func(t *testing.T) {
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, &OAuth2DefaultTarget{Audience: "api://orders"}),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("all providers use jwt-bearer — audience is optional there", func(t *testing.T) {
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantJWTBearer, nil),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("mixed grants — provider selection is a request-time decision", func(t *testing.T) {
		// The jwt-bearer provider may be the one that matches; not provable at load.
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, nil),
			exchangeProvider("entra", OAuth2ProviderGrantJWTBearer, nil),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("a sibling override supplies an audience — the working endpoints stay up", func(t *testing.T) {
		// listOrders keeps failing at request time; rejecting the document
		// would take the working getOrders offline too.
		enabled := true
		mw := &Middleware{Operations: Operations{
			"getOrders":  &Operation{Exchange: &OAuth2Exchange{Enabled: &enabled, Audience: "api://orders"}},
			"listOrders": &Operation{Exchange: &OAuth2Exchange{Enabled: &enabled}},
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", rfc8693NoDefault()), mw)
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})

	t.Run("token exchange disabled entirely", func(t *testing.T) {
		te := &OAuth2TokenExchange{Enabled: false, Providers: []OAuth2TokenExchangeProvider{
			exchangeProvider("primary", OAuth2ProviderGrantTokenExchange, nil),
		}}
		s := withMiddleware(newOAuth2WithTokenExchange("corpOAuth", te), activeExchangeOp(""))
		assert.NoError(t, s.ValidateOAuth2Schemes())
	})
}

func TestIsResourceIndicator(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://orders.example.com", true},
		{"https://orders.example.com/v1?x=1", true},
		{"api://orders", true},
		{"urn:example:orders", true},
		{"abc123", false},
		{"/relative/path", false},
		{"https://orders.example.com#frag", false},
		{"https://orders.example.com#", false},
		{"HTTPS://orders.example.com", true},
		{"https:", false},
		{"https://", false},
		{"https:///path", false},
		{"x:", false},
		{"urn:a urn:b", false},
		{"https://x/a b", false},
		{"https://x/\ta", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, IsResourceIndicator(tc.in))
		})
	}
}

func TestValidateOAuth2Schemes_Resources(t *testing.T) {
	validate := func(provider OAuth2TokenExchangeProvider, mw *Middleware) error {
		te := &OAuth2TokenExchange{Enabled: true, Providers: []OAuth2TokenExchangeProvider{provider}}
		s := newOAuth2WithTokenExchange("corpOAuth", te)
		if mw != nil {
			s = withMiddleware(s, mw)
		}
		return s.ValidateOAuth2Schemes()
	}
	opWithResources := func(resources ...string) *Middleware {
		mw := activeExchangeOp("abc123")
		mw.Operations["getOrders"].Exchange.Resources = resources
		return mw
	}
	enabled := true
	mcpWithResources := func(resources ...string) *Middleware {
		return &Middleware{McpTools: MCPPrimitives{
			"searchOrders": &MCPPrimitive{Operation: Operation{Exchange: &OAuth2Exchange{Enabled: &enabled, Audience: "abc123", Resources: resources}}},
		}}
	}
	defaultTarget := func(resources ...string) *OAuth2DefaultTarget {
		return &OAuth2DefaultTarget{Audience: "abc123", Resources: resources}
	}

	t.Run("accepted", func(t *testing.T) {
		tests := []struct {
			name     string
			provider OAuth2TokenExchangeProvider
			mw       *Middleware
		}{
			{"provider default list", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget("https://orders.example.com", "api://orders", "urn:example:orders")), nil},
			{"operation list", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget()), opWithResources("https://orders.example.com")},
			{"MCP primitive list", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget()), mcpWithResources("https://orders.example.com")},
			{"operation list beside a jwt-bearer provider is ignored, not rejected", exchangeProvider("p", OAuth2ProviderGrantJWTBearer, nil), opWithResources("https://orders.example.com")},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				assert.NoError(t, validate(tc.provider, tc.mw))
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		tests := []struct {
			name     string
			provider OAuth2TokenExchangeProvider
			mw       *Middleware
			wantErr  string
		}{
			{"relative provider value", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget("orders")), nil, `defaultTarget.resources entry "orders"`},
			{"provider value with a fragment", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget("https://orders.example.com#x")), nil, "absolute URI without a fragment"},
			{"empty provider value", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget("")), nil, `defaultTarget.resources entry ""`},
			{"jwt-bearer provider with resources", exchangeProvider("p", OAuth2ProviderGrantJWTBearer, defaultTarget("https://orders.example.com")), nil, "remove defaultTarget.resources"},
			{"relative operation value", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget()), opWithResources("/orders"), `exchange on "getOrders" resources entry "/orders"`},
			{"MCP primitive value with a fragment", exchangeProvider("p", OAuth2ProviderGrantTokenExchange, defaultTarget()), mcpWithResources("api://orders#tool"), `exchange on "searchOrders"`},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := validate(tc.provider, tc.mw)
				require.Error(t, err)
				assert.Contains(t, err.Error(), `oauth2 scheme "corpOAuth"`)
				assert.Contains(t, err.Error(), tc.wantErr)
			})
		}
	})
}

func TestOAuth2Exchange_RoundTripPreservesResources(t *testing.T) {
	in := OAuth2TokenExchangeProvider{DefaultTarget: &OAuth2DefaultTarget{Audience: "abc123", Resources: []string{"https://a", "https://b"}}}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"resources":["https://a","https://b"]`)

	var out OAuth2TokenExchangeProvider
	require.NoError(t, json.Unmarshal(b, &out))
	assert.Equal(t, in.DefaultTarget.Resources, out.DefaultTarget.Resources)

	b, err = json.Marshal(OAuth2Exchange{Audience: "abc123"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "resources")
}
