package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestAuthentication(t *testing.T) {
	var emptyAuthentication Authentication

	var convertedAPI apidef.APIDefinition
	emptyAuthentication.ExtractTo(&convertedAPI)

	var resultAuthentication Authentication
	resultAuthentication.Fill(convertedAPI)

	assert.Equal(t, emptyAuthentication, resultAuthentication)
}

func TestScopes(t *testing.T) {
	var emptyScopes Scopes

	scopeClaim := apidef.ScopeClaim{}
	emptyScopes.ExtractTo(&scopeClaim)

	var resultScopes Scopes
	resultScopes.Fill(&scopeClaim)

	assert.Equal(t, emptyScopes, resultScopes)
}

func TestAuthSources(t *testing.T) {
	var emptyAuthSources AuthSources

	var convertedAuthConfig apidef.AuthConfig
	emptyAuthSources.ExtractTo(&convertedAuthConfig)

	var resultAuthSources AuthSources
	resultAuthSources.Fill(convertedAuthConfig)

	assert.Equal(t, emptyAuthSources, resultAuthSources)
}

func TestAuthSource(t *testing.T) {
	t.Run("param", func(t *testing.T) {
		var emptyParamSource AuthSource

		var convertedAuthConfig apidef.AuthConfig
		emptyParamSource.ExtractTo(&convertedAuthConfig.UseParam, &convertedAuthConfig.ParamName)

		var resultParamSource AuthSource
		resultParamSource.Fill(convertedAuthConfig.UseParam, convertedAuthConfig.ParamName)

		assert.Equal(t, emptyParamSource, resultParamSource)
	})

	t.Run("cookie", func(t *testing.T) {
		var emptyCookieSource AuthSource

		var convertedAuthConfig apidef.AuthConfig
		emptyCookieSource.ExtractTo(&convertedAuthConfig.UseCookie, &convertedAuthConfig.CookieName)

		var resultCookieSource AuthSource
		resultCookieSource.Fill(convertedAuthConfig.UseCookie, convertedAuthConfig.CookieName)

		assert.Equal(t, emptyCookieSource, resultCookieSource)
	})
}

func TestSignature(t *testing.T) {
	var emptySignature Signature

	var convertedAuthConfig apidef.AuthConfig
	emptySignature.ExtractTo(&convertedAuthConfig)

	var resultSignature Signature
	resultSignature.Fill(convertedAuthConfig)

	assert.Equal(t, emptySignature, resultSignature)
}

func TestHMAC(t *testing.T) {
	var emptyHMAC HMAC

	var convertedAPI apidef.APIDefinition
	emptyHMAC.ExtractTo(&convertedAPI)

	var resultHMAC HMAC
	resultHMAC.Fill(convertedAPI)

	assert.Equal(t, emptyHMAC, resultHMAC)
}

func TestOIDC(t *testing.T) {
	var emptyOIDC OIDC

	var convertedAPI apidef.APIDefinition
	emptyOIDC.ExtractTo(&convertedAPI)

	var resultOIDC OIDC
	emptyOIDC.Fill(convertedAPI)

	assert.Equal(t, emptyOIDC, resultOIDC)
}

func TestCustomPlugin(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyCustomPlugin CustomPluginAuthentication

		var convertedAPI apidef.APIDefinition
		convertedAPI.SetDisabledFlags()
		emptyCustomPlugin.ExtractTo(&convertedAPI)

		var resultCustomPlugin CustomPluginAuthentication
		resultCustomPlugin.Fill(convertedAPI)

		assert.Equal(t, emptyCustomPlugin, resultCustomPlugin)
	})

	t.Run("values", func(t *testing.T) {
		t.Run("goplugin", func(t *testing.T) {
			var expectedCustomPluginAuth = CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:      true,
					FunctionName: "Auth",
					Path:         "/path/to/plugin",
				},
			}

			var convertedAPI apidef.APIDefinition
			convertedAPI.SetDisabledFlags()
			expectedCustomPluginAuth.ExtractTo(&convertedAPI)

			var actualCustomPluginAuth CustomPluginAuthentication
			actualCustomPluginAuth.Fill(convertedAPI)

			assert.Equal(t, expectedCustomPluginAuth, actualCustomPluginAuth)
			assert.Empty(t, actualCustomPluginAuth.AuthSources)
		})

		t.Run("coprocess", func(t *testing.T) {
			var expectedCustomPluginAuth = CustomPluginAuthentication{
				Enabled: true,
				Config: &AuthenticationPlugin{
					Enabled:      true,
					FunctionName: "Auth",
					Path:         "/path/to/plugin",
				},
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
						Name:    "Authorization",
					},
				},
			}

			var convertedAPI apidef.APIDefinition
			convertedAPI.SetDisabledFlags()
			expectedCustomPluginAuth.ExtractTo(&convertedAPI)

			var actualCustomPluginAuth CustomPluginAuthentication
			actualCustomPluginAuth.Fill(convertedAPI)

			assert.Equal(t, expectedCustomPluginAuth, actualCustomPluginAuth)
			assert.NotEmpty(t, actualCustomPluginAuth.AuthSources)
		})
	})

}
