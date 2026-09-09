package oas

import (
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuth2PRM_GetWellKnownPath(t *testing.T) {
	var nilPRM *OAuth2PRM
	assert.Equal(t, DefaultPRMWellKnownPath, nilPRM.GetWellKnownPath())
	assert.Equal(t, DefaultPRMWellKnownPath, (&OAuth2PRM{}).GetWellKnownPath())
	assert.Equal(t, ".well-known/custom-prm", (&OAuth2PRM{WellKnownPath: ".well-known/custom-prm"}).GetWellKnownPath())
}

func TestOAuth2PRM_IsAutoDeriveScopes(t *testing.T) {
	var nilPRM *OAuth2PRM
	assert.True(t, nilPRM.IsAutoDeriveScopes())
	assert.True(t, (&OAuth2PRM{}).IsAutoDeriveScopes(), "nil pointer defaults to true")

	off := false
	assert.False(t, (&OAuth2PRM{AutoDeriveScopes: &off}).IsAutoDeriveScopes())
	on := true
	assert.True(t, (&OAuth2PRM{AutoDeriveScopes: &on}).IsAutoDeriveScopes())
}

func TestOAuth2_HasContentRecognisesPRM(t *testing.T) {
	o := &OAuth2{ProtectedResourceMetadata: &OAuth2PRM{Enabled: true}}
	assert.True(t, o.HasContent())
	assert.False(t, o.IsEmpty())
}

// A raw scheme map carrying only protectedResourceMetadata (no
// scopeCheck) must still type as *OAuth2 after a JSON round-trip.
func TestOAuth2_RoundTripJSONPreservesPRMOnlyScheme(t *testing.T) {
	s := newOAuth2Fixture("corpOAuth")
	cfg := s.GetTykOAuth2Config("corpOAuth")
	cfg.ProtectedResourceMetadata = &OAuth2PRM{
		Enabled:              true,
		WellKnownPath:        ".well-known/oauth-protected-resource",
		Resource:             "https://api.example.com/",
		AuthorizationServers: []string{"https://idp.example.com"},
	}

	b, err := json.Marshal(s)
	require.NoError(t, err)

	var out OAS
	require.NoError(t, json.Unmarshal(b, &out))
	require.True(t, out.IsOAuth2Scheme("corpOAuth"))
	got := out.GetTykOAuth2Config("corpOAuth")
	require.NotNil(t, got.ProtectedResourceMetadata)
	assert.True(t, got.ProtectedResourceMetadata.Enabled)
	assert.Equal(t, "https://api.example.com/", got.ProtectedResourceMetadata.Resource)
	assert.Equal(t, []string{"https://idp.example.com"}, got.ProtectedResourceMetadata.AuthorizationServers)
}

// withOAuth2Catalog adds an OAS components.securitySchemes entry for the
// named oauth2 scheme carrying an operator-authored flows.scopes catalog.
func withOAuth2Catalog(s *OAS, name string, catalog map[string]string) {
	if s.Components == nil {
		s.Components = &openapi3.Components{}
	}
	if s.Components.SecuritySchemes == nil {
		s.Components.SecuritySchemes = openapi3.SecuritySchemes{}
	}
	s.Components.SecuritySchemes[name] = &openapi3.SecuritySchemeRef{
		Value: &openapi3.SecurityScheme{
			Type: typeOAuth2,
			Flows: &openapi3.OAuthFlows{
				AuthorizationCode: &openapi3.OAuthFlow{
					AuthorizationURL: "/oauth/authorize",
					TokenURL:         "/oauth/token",
					Scopes:           catalog,
				},
			},
		},
	}
}

// prmFixture builds an OAS doc with the new oauth2 PRM block, an
// operator-authored flows.scopes catalog ({audit:read, audit:write}), a
// root security: baseline ({api:access}), and per-op security: arrays
// ({users:read}, {users:write}).
func prmFixture(t *testing.T, autoDerive *bool) *OAS {
	t.Helper()
	s := newOAuth2Fixture("corpOAuth")
	cfg := s.GetTykOAuth2Config("corpOAuth")
	cfg.ScopeCheck = &OAuth2ScopeCheck{Enabled: true}
	s.Security = append(s.Security, openapi3.SecurityRequirement{"corpOAuth": {"api:access"}})
	cfg.ProtectedResourceMetadata = &OAuth2PRM{
		Enabled:          true,
		AutoDeriveScopes: autoDerive,
	}
	withOAuth2Catalog(s, "corpOAuth", map[string]string{"audit:read": "", "audit:write": ""})

	s.Paths = openapi3.NewPaths()
	get := &openapi3.PathItem{Get: &openapi3.Operation{Security: &openapi3.SecurityRequirements{
		{"corpOAuth": {"users:read"}},
	}}}
	post := &openapi3.PathItem{Post: &openapi3.Operation{Security: &openapi3.SecurityRequirements{
		{"corpOAuth": {"users:write"}},
	}}}
	s.Paths.Set("/users/{id}", get)
	s.Paths.Set("/users", post)
	return s
}

func TestOAS_OAuth2PRMScopesSupported_Union(t *testing.T) {
	t.Run("auto-derive default — catalog unioned with root + per-op security", func(t *testing.T) {
		s := prmFixture(t, nil)
		assert.Equal(t,
			[]string{"api:access", "audit:read", "audit:write", "users:read", "users:write"},
			s.OAuth2PRMScopesSupported("corpOAuth"))
	})

	t.Run("auto-derive off — catalog only", func(t *testing.T) {
		off := false
		s := prmFixture(t, &off)
		assert.Equal(t,
			[]string{"audit:read", "audit:write"},
			s.OAuth2PRMScopesSupported("corpOAuth"))
	})

	t.Run("no PRM block — nil", func(t *testing.T) {
		s := newOAuth2Fixture("corpOAuth")
		assert.Nil(t, s.OAuth2PRMScopesSupported("corpOAuth"))
	})

	t.Run("unknown scheme — nil", func(t *testing.T) {
		s := prmFixture(t, nil)
		assert.Nil(t, s.OAuth2PRMScopesSupported("nope"))
	})

	t.Run("no catalog and auto-derive off — nil", func(t *testing.T) {
		off := false
		s := newOAuth2Fixture("corpOAuth")
		cfg := s.GetTykOAuth2Config("corpOAuth")
		cfg.ProtectedResourceMetadata = &OAuth2PRM{Enabled: true, AutoDeriveScopes: &off}
		assert.Nil(t, s.OAuth2PRMScopesSupported("corpOAuth"))
	})
}

// The catalog is read from whichever OAuth2 flow the operator declared
// it under — not only authorizationCode.
func TestOAS_OAuth2PRMScopesSupported_ReadsClientCredentialsFlow(t *testing.T) {
	off := false
	s := newOAuth2Fixture("corpOAuth")
	cfg := s.GetTykOAuth2Config("corpOAuth")
	cfg.ProtectedResourceMetadata = &OAuth2PRM{Enabled: true, AutoDeriveScopes: &off}
	s.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			"corpOAuth": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{
				Type: typeOAuth2,
				Flows: &openapi3.OAuthFlows{
					ClientCredentials: &openapi3.OAuthFlow{
						TokenURL: "/oauth/token",
						Scopes:   map[string]string{"svc:read": "", "svc:write": ""},
					},
				},
			}},
		},
	}
	assert.Equal(t, []string{"svc:read", "svc:write"}, s.OAuth2PRMScopesSupported("corpOAuth"))
}
