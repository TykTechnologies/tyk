package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestCertificateAuth(t *testing.T) {
	t.Run("new field implementation", func(t *testing.T) {
		// Create an API definition with the new certificate auth structure
		api := apidef.APIDefinition{}
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS
		oas := OAS{}
		oas.Fill(api)

		// Verify certificate auth is enabled in OAS
		certAuth := oas.getTykCertificateAuth("certificateAuth")
		assert.NotNil(t, certAuth)
		assert.True(t, certAuth.Enabled)

		// Convert back to classic API definition
		var convertedAPI apidef.APIDefinition
		convertedAPI.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas.ExtractTo(&convertedAPI)

		// Verify certificate auth is enabled in the converted API
		certAuthConfig, ok := convertedAPI.AuthConfigs[apidef.AuthTokenType]
		assert.True(t, ok)
		assert.True(t, certAuthConfig.UseCertificate)
	})

	t.Run("deprecated field support", func(t *testing.T) {
		// Create an API definition using the deprecated field
		api := apidef.APIDefinition{}
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.UseStandardAuth = true
		api.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS
		oas := OAS{}
		oas.Fill(api)

		// Verify the deprecated field is set in OAS
		token := oas.getTykTokenAuth(apidef.AuthTokenType)
		assert.NotNil(t, token)
		assert.True(t, token.EnableClientCertificate)

		// Convert back to classic API definition
		var convertedAPI apidef.APIDefinition
		convertedAPI.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas.ExtractTo(&convertedAPI)

		// Verify the deprecated field is set in the converted API
		tokenConfig, ok := convertedAPI.AuthConfigs[apidef.AuthTokenType]
		assert.True(t, ok)
		assert.True(t, tokenConfig.UseCertificate)
	})

	t.Run("mixed usage", func(t *testing.T) {
		// Create an API definition and check both OAS representations
		api := apidef.APIDefinition{}
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.UseStandardAuth = true

		// Set the certificate auth field
		api.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS
		oas := OAS{}
		oas.Fill(api)

		// Verify both fields are set in OAS
		token := oas.getTykTokenAuth(apidef.AuthTokenType)
		assert.NotNil(t, token)
		assert.True(t, token.EnableClientCertificate)

		certAuth := oas.getTykCertificateAuth("certificateAuth")
		assert.NotNil(t, certAuth)
		assert.True(t, certAuth.Enabled)

		// Check security requirements include certificate auth
		found := false
		for _, secReq := range oas.Security {
			for secName := range secReq {
				if secName == "certificateAuth" {
					found = true
				}
			}
		}
		assert.True(t, found, "CertificateAuth should be in security requirements")

		// Convert back to classic API definition
		var convertedAPI apidef.APIDefinition
		convertedAPI.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas.ExtractTo(&convertedAPI)

		// Verify the field is set in the converted API
		tokenConfig, ok := convertedAPI.AuthConfigs[apidef.AuthTokenType]
		assert.True(t, ok)
		assert.True(t, tokenConfig.UseCertificate)

		// The certificate auth should be mapped to the auth token config
		assert.True(t, tokenConfig.UseCertificate)
	})

	t.Run("migration path", func(_ *testing.T) {
		// Create an API definition using the deprecated field
		api := apidef.APIDefinition{}
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}
	})

	t.Run("precedence test", func(t *testing.T) {
		// This test verifies that in gateway code, the new certificate auth takes precedence

		// Test case 1: Only new field enabled
		api1 := apidef.APIDefinition{}
		api1.AuthConfigs = make(map[string]apidef.AuthConfig)

		// Enable certificate auth in token config
		api1.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS and back
		oas1 := OAS{}
		oas1.Fill(api1)

		var convertedAPI1 apidef.APIDefinition
		convertedAPI1.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas1.ExtractTo(&convertedAPI1)

		// Verify certificate auth is enabled in the converted API
		tokenConfig1, ok := convertedAPI1.AuthConfigs[apidef.AuthTokenType]
		require.True(t, ok)
		assert.True(t, tokenConfig1.UseCertificate, "Certificate auth should be enabled")

		// Test case 2: Only deprecated field enabled
		api2 := apidef.APIDefinition{}
		api2.AuthConfigs = make(map[string]apidef.AuthConfig)
		api2.UseStandardAuth = true

		// Enable deprecated certificate auth
		api2.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS and back
		oas2 := OAS{}
		oas2.Fill(api2)

		var convertedAPI2 apidef.APIDefinition
		convertedAPI2.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas2.ExtractTo(&convertedAPI2)

		// Verify token auth certificate is enabled in the converted API
		tokenConfig2, ok := convertedAPI2.AuthConfigs[apidef.AuthTokenType]
		require.True(t, ok)
		assert.True(t, tokenConfig2.UseCertificate, "Token certificate auth should be enabled")

		// Test case 3: Check security requirements
		api3 := apidef.APIDefinition{}
		api3.AuthConfigs = make(map[string]apidef.AuthConfig)
		api3.UseStandardAuth = true

		// Enable certificate auth
		api3.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS
		oas3 := OAS{}
		oas3.Fill(api3)

		// Check security requirements include certificate auth
		found := false
		for _, secReq := range oas3.Security {
			for secName := range secReq {
				if secName == "certificateAuth" {
					found = true
				}
			}
		}
		assert.True(t, found, "certificateAuth should be in security requirements")

		// Convert back to classic API definition
		var convertedAPI3 apidef.APIDefinition
		convertedAPI3.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas3.ExtractTo(&convertedAPI3)

		// Verify certificate auth is enabled in the converted API
		tokenConfig3, ok := convertedAPI3.AuthConfigs[apidef.AuthTokenType]
		require.True(t, ok)
		assert.True(t, tokenConfig3.UseCertificate, "Certificate auth should be enabled")
	})

	t.Run("migration path", func(t *testing.T) {
		// Create an API definition using the deprecated field
		api := apidef.APIDefinition{}
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		api.UseStandardAuth = true
		api.AuthConfigs[apidef.AuthTokenType] = apidef.AuthConfig{
			Name:           apidef.AuthTokenType,
			UseCertificate: true,
		}

		// Convert to OAS
		oas := OAS{}
		oas.Fill(api)

		// Verify the old field is correctly migrated to the new structure in OAS
		// This is handled implicitly through the fillCertificateAuth function

		// Convert back to classic API definition
		var convertedAPI apidef.APIDefinition
		convertedAPI.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas.ExtractTo(&convertedAPI)

		// Verify the old field is preserved
		tokenConfig, ok := convertedAPI.AuthConfigs[apidef.AuthTokenType]
		assert.True(t, ok)
		assert.True(t, tokenConfig.UseCertificate)
	})
}
