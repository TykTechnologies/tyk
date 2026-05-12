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
		ScopesSupported:      []string{"audit:read"},
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
	assert.Equal(t, []string{"audit:read"}, got.ProtectedResourceMetadata.ScopesSupported)
}

// prmFixture builds an OAS doc with the new oauth2 PRM block plus a
// global scopeCheck baseline and a per-op security: array.
func prmFixture(t *testing.T, autoDerive *bool) *OAS {
	t.Helper()
	s := newOAuth2Fixture("corpOAuth")
	cfg := s.GetTykOAuth2Config("corpOAuth")
	cfg.ScopeCheck = &OAuth2ScopeCheck{Enabled: true, Scopes: [][]string{{"api:access"}}}
	cfg.ProtectedResourceMetadata = &OAuth2PRM{
		Enabled:          true,
		ScopesSupported:  []string{"audit:read", "audit:write"},
		AutoDeriveScopes: autoDerive,
	}

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
	t.Run("auto-derive default — manual + baseline + per-op", func(t *testing.T) {
		s := prmFixture(t, nil)
		assert.Equal(t,
			[]string{"api:access", "audit:read", "audit:write", "users:read", "users:write"},
			s.OAuth2PRMScopesSupported("corpOAuth"))
	})

	t.Run("auto-derive off — only manual + baseline", func(t *testing.T) {
		off := false
		s := prmFixture(t, &off)
		assert.Equal(t,
			[]string{"api:access", "audit:read", "audit:write"},
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
}
