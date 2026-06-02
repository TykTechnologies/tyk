package gateway

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func TestAPISpec_APIType(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *APISpec
		expected string
	}{
		{
			name: "classic API",
			setup: func() *APISpec {
				return &APISpec{APIDefinition: &apidef.APIDefinition{}}
			},
			expected: "classic",
		},
		{
			name: "OAS API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.IsOAS = true
				return spec
			},
			expected: "oas",
		},
		{
			name: "GraphQL API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.GraphQL.Enabled = true
				return spec
			},
			expected: "graphql",
		},
		{
			name: "MCP API",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.MarkAsMCP()
				return spec
			},
			expected: "mcp",
		},
		{
			name: "MCP takes precedence over OAS",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.MarkAsMCP()
				spec.IsOAS = true
				return spec
			},
			expected: "mcp",
		},
		{
			name: "GraphQL takes precedence over OAS",
			setup: func() *APISpec {
				spec := &APISpec{APIDefinition: &apidef.APIDefinition{}}
				spec.GraphQL.Enabled = true
				spec.IsOAS = true
				return spec
			},
			expected: "graphql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.setup()
			got := spec.APIType()
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestAPISpec_GetOAuth2Config walks the resolution branches:
// classic (non-OAS) APIs short-circuit; OAS APIs return ("", nil) when
// the Tyk extension or its Authentication block is absent; security
// schemes that aren't *OAuth2 are ignored; an *OAuth2 scheme is returned
// with its scheme name.
func TestAPISpec_GetOAuth2Config(t *testing.T) {
	t.Run("classic API returns empty", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: false}}
		name, cfg := spec.GetOAuth2Config()
		assert.Empty(t, name)
		assert.Nil(t, cfg)
	})

	t.Run("OAS without Tyk extension returns empty", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
		name, cfg := spec.GetOAuth2Config()
		assert.Empty(t, name)
		assert.Nil(t, cfg)
	})

	t.Run("OAS without authentication block returns empty", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{})
		name, cfg := spec.GetOAuth2Config()
		assert.Empty(t, name)
		assert.Nil(t, cfg)
	})

	t.Run("non-oauth2 schemes are skipped", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				Authentication: &oas.Authentication{
					Enabled: true,
					SecuritySchemes: oas.SecuritySchemes{
						"legacy": &oas.OAuth{Enabled: true},
					},
				},
			},
		})
		name, cfg := spec.GetOAuth2Config()
		assert.Empty(t, name)
		assert.Nil(t, cfg)
	})

	t.Run("oauth2 scheme is returned with its name", func(t *testing.T) {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
		spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
			Server: oas.Server{
				Authentication: &oas.Authentication{
					Enabled: true,
					SecuritySchemes: oas.SecuritySchemes{
						"corpOAuth": &oas.OAuth2{Enabled: true},
					},
				},
			},
		})
		name, cfg := spec.GetOAuth2Config()
		assert.Equal(t, "corpOAuth", name)
		require.NotNil(t, cfg)
		assert.True(t, cfg.Enabled)
	})
}

// TestGetOAuth2Config_AcceptsDuplicatesAndReturnsOne pins the
// uniqueness contract for oauth2 schemes: duplicates are not rejected
// at load time (matching every other auth scheme — JWT, Token, HMAC,
// Basic, OIDC, ExternalOAuth — which all silently accept duplicate
// entries in the SecuritySchemes map). GetOAuth2Config returns one of
// the configured schemes; the choice is map-iteration dependent.
func TestGetOAuth2Config_AcceptsDuplicatesAndReturnsOne(t *testing.T) {
	spec := &APISpec{APIDefinition: &apidef.APIDefinition{IsOAS: true}}
	spec.OAS.T = openapi3.T{
		OpenAPI: "3.0.3",
		Info:    &openapi3.Info{Title: "x", Version: "1.0"},
		Paths:   openapi3.NewPaths(),
	}
	spec.OAS.SetTykExtension(&oas.XTykAPIGateway{
		Server: oas.Server{
			ListenPath: oas.ListenPath{Value: "/x/"},
			Authentication: &oas.Authentication{
				Enabled: true,
				SecuritySchemes: oas.SecuritySchemes{
					"corpOAuth": &oas.OAuth2{Enabled: true},
					"altOAuth":  &oas.OAuth2{Enabled: true},
				},
			},
		},
	})

	require.NoError(t, spec.Validate(config.OASConfig{}))

	name, cfg := spec.GetOAuth2Config()
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Contains(t, []string{"corpOAuth", "altOAuth"}, name)
}
