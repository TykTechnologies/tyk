package oas

import (
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// newOAuth2Fixture builds a minimal OAS document with the OAS-native
// oauth2 scheme configured with just the master Enabled toggle.
func newOAuth2Fixture(name string) *OAS {
	s := &OAS{}
	s.OpenAPI = "3.0.3"
	s.Info = &openapi3.Info{Title: "test", Version: "1.0"}
	s.Paths = openapi3.NewPaths()
	s.SetTykExtension(&XTykAPIGateway{
		Server: Server{
			Authentication: &Authentication{
				Enabled: true,
				SecuritySchemes: SecuritySchemes{
					name: &OAuth2{Enabled: true},
				},
			},
		},
	})
	return s
}

func TestOAuth2_HasContentReflectsEnabled(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var o *OAuth2
		assert.False(t, o.HasContent())
		assert.True(t, o.IsEmpty())
	})

	t.Run("zero value — disabled", func(t *testing.T) {
		o := &OAuth2{}
		assert.False(t, o.HasContent())
		assert.True(t, o.IsEmpty())
	})

	t.Run("enabled — has content", func(t *testing.T) {
		o := &OAuth2{Enabled: true}
		assert.True(t, o.HasContent())
		assert.False(t, o.IsEmpty())
	})
}

func TestOAuth2_FillAddsOASComponentForEnabledScheme(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}

	s.fillSecurity(api)

	require.NotNil(t, s.Components, "components should be created during fill")
	require.NotNil(t, s.Components.SecuritySchemes, "securitySchemes should be created during fill")
	ref, ok := s.Components.SecuritySchemes["corpOAuth"]
	require.True(t, ok, "expected oauth2 scheme to be added to OAS Components.SecuritySchemes")
	require.NotNil(t, ref.Value)
	assert.Equal(t, typeOAuth2, ref.Value.Type)

	require.NotEmpty(t, s.Security, "OAS security requirement should reference the scheme")
	_, ok = s.Security[0]["corpOAuth"]
	assert.True(t, ok)
}

// TestOAuth2_FillUsesRelativeURLPlaceholders pins the OAS placeholder
// URLs for the materialised oauth2 scheme. The scheme MUST declare at
// least one flow per the OAS spec, and authorizationCode requires both
// authorizationUrl and tokenUrl — relative paths are used as
// stand-in values so the saved document doesn't claim an external
// "https://example.com/…" URL. Operator-configured endpoints (from
// sub-blocks that bring real endpoints) override these.
func TestOAuth2_FillUsesRelativeURLPlaceholders(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}

	s.fillSecurity(api)

	ref := s.Components.SecuritySchemes["corpOAuth"]
	require.NotNil(t, ref, "scheme should be added to Components")
	require.NotNil(t, ref.Value.Flows, "scheme should declare flows")
	require.NotNil(t, ref.Value.Flows.AuthorizationCode, "authorizationCode flow should be present")
	assert.Equal(t, "/oauth/authorize", ref.Value.Flows.AuthorizationCode.AuthorizationURL,
		"authorizationUrl should be a relative placeholder, not an external example.com URL")
	assert.Equal(t, "/oauth/token", ref.Value.Flows.AuthorizationCode.TokenURL,
		"tokenUrl should be a relative placeholder, not an external example.com URL")
}

func TestOAuth2_FillSkipsDisabledSchemeFromOASComponents(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	cfg := s.GetTykExtension().Server.Authentication.SecuritySchemes["corpOAuth"].(*OAuth2)
	cfg.Enabled = false

	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}
	s.fillSecurity(api)

	// The Tyk extension still carries the disabled config (so the
	// operator's settings round-trip), but the OAS Components should not
	// advertise a scheme that's turned off.
	if s.Components != nil && s.Components.SecuritySchemes != nil {
		_, advertised := s.Components.SecuritySchemes["corpOAuth"]
		assert.False(t, advertised,
			"disabled oauth2 scheme must not be advertised in OAS Components")
	}
}

func TestOAuth2_RoundTripJSONPreservesEnabled(t *testing.T) {
	original := newOAuth2Fixture("corpOAuth")
	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}
	original.fillSecurity(api)

	raw, err := json.Marshal(original)
	require.NoError(t, err)

	// On unmarshal, the Tyk extension comes back as a raw map until
	// the OAS is reconstituted via NewOASFromBytes / Initialize. With
	// only the master Enabled toggle set, the scheme is shape-ambiguous
	// with a legacy OAuth scheme, so the map-probe disambiguator does
	// not recognise it. This test asserts on the on-the-wire JSON
	// shape directly.
	assert.Contains(t, string(raw), `"corpOAuth":{"enabled":true}`,
		"the Tyk extension should serialise the oauth2 scheme with master Enabled set under its scheme name")
}

func TestOAuth2_IsOAuth2Scheme(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	assert.True(t, s.IsOAuth2Scheme("corpOAuth"))
	assert.False(t, s.IsOAuth2Scheme("nonexistent"))
}

// TestOAuth2_HelpersHandleMissingTykAuth pins the early-return behaviour
// of the oauth2 helpers when the Tyk extension has no authentication
// block at all. These paths fire when an OAS doc is filled or queried
// before any security configuration is layered in.
func TestOAuth2_HelpersHandleMissingTykAuth(t *testing.T) {
	s := &OAS{}
	s.SetTykExtension(&XTykAPIGateway{})

	assert.NotPanics(t, s.fillOAuth2, "fillOAuth2 must short-circuit when authentication is absent")
	assert.Nil(t, s.GetTykOAuth2Config("anything"))
}

// TestOAuth2_GetTykOAuth2ConfigIgnoresOtherSchemeTypes pins that a
// security scheme entry typed as something other than *OAuth2 (e.g. a
// legacy *OAuth) does not satisfy IsOAuth2Scheme.
func TestOAuth2_GetTykOAuth2ConfigIgnoresOtherSchemeTypes(t *testing.T) {
	s := &OAS{}
	s.SetTykExtension(&XTykAPIGateway{
		Server: Server{
			Authentication: &Authentication{
				Enabled: true,
				SecuritySchemes: SecuritySchemes{
					"legacy": &OAuth{Enabled: true},
				},
			},
		},
	})

	assert.Nil(t, s.GetTykOAuth2Config("legacy"))
	assert.False(t, s.IsOAuth2Scheme("legacy"))
}

// TestOAuth2_FillOAuth2OASSchemeCreatesComponents pins that calling
// fillOAuth2OASScheme directly on an OAS with no Components block lazily
// creates one. The normal fillSecurity flow pre-initialises Components,
// but the helper is reachable from sub-block fill paths and must stand
// on its own.
func TestOAuth2_FillOAuth2OASSchemeCreatesComponents(t *testing.T) {
	s := &OAS{}
	require.Nil(t, s.Components)

	s.fillOAuth2OASScheme("corpOAuth", &OAuth2{Enabled: true})

	require.NotNil(t, s.Components)
	require.NotNil(t, s.Components.SecuritySchemes)
	ref, ok := s.Components.SecuritySchemes["corpOAuth"]
	require.True(t, ok)
	assert.Equal(t, typeOAuth2, ref.Value.Type)
}

func TestOAuth2_HasContentRecognisesScopeCheck(t *testing.T) {
	// A scheme with Enabled=false but ScopeCheck configured still
	// counts as "has content" so map-probe disambiguation can detect
	// it as an OAS-native oauth2 scheme rather than a legacy OAuth one.
	o := &OAuth2{ScopeCheck: &OAuth2ScopeCheck{Enabled: true}}
	assert.True(t, o.HasContent())
}

// TestOAuth2_FillAggregatesFlowScopesFromRootSecurity pins that the
// scope vocabulary on the materialised OAS scheme is aggregated from
// every scope referenced for this scheme by the root `security:`
// array. Operators declare required scopes once (in `security:`) and
// OAS tooling sees the same vocabulary.
func TestOAuth2_FillAggregatesFlowScopesFromRootSecurity(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	s.Security = openapi3.SecurityRequirements{
		{"corpOAuth": []string{"read:billing", "write:billing"}},
		{"corpOAuth": []string{"admin"}},
	}

	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}
	s.fillSecurity(api)

	ref := s.Components.SecuritySchemes["corpOAuth"]
	require.NotNil(t, ref.Value.Flows)
	require.NotNil(t, ref.Value.Flows.AuthorizationCode)
	scopes := ref.Value.Flows.AuthorizationCode.Scopes
	require.NotNil(t, scopes)
	_, hasRead := scopes["read:billing"]
	_, hasWrite := scopes["write:billing"]
	_, hasAdmin := scopes["admin"]
	assert.True(t, hasRead, "flows.scopes should contain read:billing from the first requirement")
	assert.True(t, hasWrite, "flows.scopes should contain write:billing from the first requirement")
	assert.True(t, hasAdmin, "flows.scopes should contain admin from the second requirement")
}

// TestOAuth2_FillPreservesExistingScopeDescriptions pins that operator-
// authored scope descriptions on the OAS scheme survive fill — only
// the scope-name set is reconciled with `security:`.
func TestOAuth2_FillPreservesExistingScopeDescriptions(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	s.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			"corpOAuth": &openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{
					Type: typeOAuth2,
					Flows: &openapi3.OAuthFlows{
						AuthorizationCode: &openapi3.OAuthFlow{
							AuthorizationURL: "/oauth/authorize",
							TokenURL:         "/oauth/token",
							Scopes: map[string]string{
								"read:billing": "Read billing records",
							},
						},
					},
				},
			},
		},
	}
	s.Security = openapi3.SecurityRequirements{
		{"corpOAuth": []string{"read:billing", "admin"}},
	}

	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}
	s.fillSecurity(api)

	scopes := s.Components.SecuritySchemes["corpOAuth"].Value.Flows.AuthorizationCode.Scopes
	assert.Equal(t, "Read billing records", scopes["read:billing"], "existing description should survive fill")
	assert.Equal(t, "", scopes["admin"], "newly added scope gets an empty description")
}

func TestOAuth2ScopeCheck_RoundTripJSONPreservesAllFields(t *testing.T) {
	original := newOAuth2Fixture("corpOAuth")
	cfg := original.GetTykExtension().Server.Authentication.SecuritySchemes["corpOAuth"].(*OAuth2)
	cfg.ScopeCheck = &OAuth2ScopeCheck{
		Enabled:     true,
		ClaimNames:  []string{"scope", "scp", "permissions"},
		Separator:   ",",
		ScopeSource: OAuth2ScopeSourceUnion,
	}

	raw, err := json.Marshal(original)
	require.NoError(t, err)

	// scopeCheck serialises every token-side field operator-set.
	// Required scopes live in OAS root `security:`, not on the scheme.
	str := string(raw)
	assert.Contains(t, str, `"scopeCheck"`)
	assert.Contains(t, str, `"claimNames":["scope","scp","permissions"]`)
	assert.Contains(t, str, `"separator":","`)
	assert.Contains(t, str, `"scopeSource":"union"`)
	assert.NotContains(t, str, `"scopes":[[`, "scopeCheck must not carry a scopes array — required scopes live in OAS root security:")
}

// TestOAuth2_FillExtractPreservesSchemeNameVerbatim pins the contract
// that the scheme name (the key under components.securitySchemes and
// the Tyk extension securitySchemes map) is treated as opaque data
// and round-trips byte-for-byte. The contract is name-agnostic per
// the OpenAPI 3.x spec, so dashes, mixed casing, and prefix-like
// substrings of "oauth2" must all survive without normalisation.
// Pair with the gateway side `TestOAuth2Middleware_NameAgnostic`.
func TestOAuth2_FillExtractPreservesSchemeNameVerbatim(t *testing.T) {
	const exotic = "Prct-OAuth2-Edge_42"

	s := newOAuth2Fixture(exotic)
	cfg := s.GetTykExtension().Server.Authentication.SecuritySchemes[exotic].(*OAuth2)
	cfg.ScopeCheck = &OAuth2ScopeCheck{
		Enabled:     true,
		ScopeSource: OAuth2ScopeSourceGlobal,
	}

	api := apidef.APIDefinition{AuthConfigs: map[string]apidef.AuthConfig{}}
	s.fillSecurity(api)

	// Fill side: the OAS Components and root security: reference the
	// scheme under the exotic name exactly.
	require.NotNil(t, s.Components, "components should be created during fill")
	_, ok := s.Components.SecuritySchemes[exotic]
	assert.True(t, ok, "expected fill to materialise components.securitySchemes[%q]", exotic)

	require.NotEmpty(t, s.Security, "fill should add a root security: requirement")
	_, ok = s.Security[0][exotic]
	assert.True(t, ok, "expected root security[0] to reference %q", exotic)

	// No accidental normalisation — neither lowercased nor stripped.
	for _, alias := range []string{"oauth2", "prct-oauth2-edge_42", "Prct-OAuth2-Edge42"} {
		_, found := s.Components.SecuritySchemes[alias]
		assert.False(t, found, "fill must not materialise an aliased name %q", alias)
	}
}

func TestOAS_DeriveOAuth2Scopes_NoOAuth2Scheme(t *testing.T) {
	s := &OAS{}
	s.OpenAPI = "3.0.3"
	s.Info = &openapi3.Info{Title: "test", Version: "1.0"}
	s.Security = openapi3.SecurityRequirements{{"jwtAuth": {"x"}}}
	assert.Empty(t, s.SortedOAuth2Scopes())
}

func TestOAS_DeriveOAuth2Scopes_RootPerOpAndMCP(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	s.Security = openapi3.SecurityRequirements{
		{"corpOAuth": {"api:access"}},
		{"jwtAuth": {"ignored"}},
	}

	s.Paths = openapi3.NewPaths()
	pi := &openapi3.PathItem{}
	pi.Get = &openapi3.Operation{Security: &openapi3.SecurityRequirements{
		{"corpOAuth": {"users:read"}},
		{"corpOAuth": {"users:all"}},
	}}
	s.Paths.Set("/users", pi)

	ext := s.GetTykExtension()
	ext.Middleware = &Middleware{
		McpTools: MCPPrimitives{
			"create_user": {Security: openapi3.SecurityRequirements{{"corpOAuth": {"users:write"}}}},
		},
		McpResources: MCPPrimitives{
			"file": {Security: openapi3.SecurityRequirements{{"corpOAuth": {"files:read"}}}},
		},
	}

	assert.Equal(t, []string{"api:access", "files:read", "users:all", "users:read", "users:write"}, s.SortedOAuth2Scopes())
}

func TestMCPPrimitive_RoundTripJSONPreservesSecurity(t *testing.T) {
	p := &MCPPrimitive{Security: openapi3.SecurityRequirements{
		{"corpOAuth": {"users:write", "audit:write"}},
		{"corpOAuth": {"admin"}},
	}}
	b, err := json.Marshal(p)
	require.NoError(t, err)

	var out MCPPrimitive
	require.NoError(t, json.Unmarshal(b, &out))
	require.Len(t, out.Security, 2)
	assert.Equal(t, []string{"users:write", "audit:write"}, out.Security[0]["corpOAuth"])
	assert.Equal(t, []string{"admin"}, out.Security[1]["corpOAuth"])
}

// TestScopeCheck_RoundTrip pins that the per-operation scopeCheck block
// survives a JSON round-trip and is omitted when absent.
func TestScopeCheck_RoundTrip(t *testing.T) {
	op := Operation{ScopeCheck: &ScopeCheck{Enabled: false}}

	data, err := json.Marshal(op)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"scopeCheck":{"enabled":false}`)

	var got Operation
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, op.ScopeCheck, got.ScopeCheck)

	empty, err := json.Marshal(Operation{})
	require.NoError(t, err)
	assert.NotContains(t, string(empty), "scopeCheck")
}
