package oas

import (
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// newOAuth2Fixture builds a minimal OAS document with the new oauth2
// scheme configured with just the master Enabled toggle.
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
// "https://example.com/…" URL. Operator-configured endpoints (in
// follow-up sub-blocks) will override these.
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

	// On unmarshal, the Tyk extension comes back as a raw map until the
	// OAS is reconstituted via NewOASFromBytes / Initialize. With only
	// the master Enabled toggle set, the scheme is shape-ambiguous with
	// a legacy OAuth scheme so no map-probe disambiguator recognises
	// it; this test asserts on the on-the-wire JSON shape directly.
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
