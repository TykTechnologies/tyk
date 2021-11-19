package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestAuthentication(t *testing.T) {
	var emptyAuthentication Authentication

	var convertedAPI apidef.APIDefinition
	emptyAuthentication.ExtractTo(&convertedAPI)

	var resultAuthentication Authentication
	resultAuthentication.Fill(convertedAPI)

	assert.Equal(t, emptyAuthentication, resultAuthentication)

	t.Run("Fill just GoPlugin", func(t *testing.T) {
		// GoPlugin is different from others, it is not set inside AuthConfigs.

		goPluginAuth := Authentication{GoPlugin: &GoPlugin{Enabled: true}}

		goPluginAuth.ExtractTo(&convertedAPI)

		resultAuthentication.Fill(convertedAPI)

		assert.Equal(t, goPluginAuth, resultAuthentication)
	})
}

func TestToken(t *testing.T) {
	var emptyToken Token

	var convertedAPI apidef.APIDefinition
	emptyToken.ExtractTo(&convertedAPI)

	var resultToken Token
	resultToken.Fill(convertedAPI.UseStandardAuth, convertedAPI.AuthConfigs["authToken"])

	assert.Equal(t, emptyToken, resultToken)
}

func TestJWT(t *testing.T) {
	var emptyJWT JWT

	var convertedAPI apidef.APIDefinition
	emptyJWT.ExtractTo(&convertedAPI)

	var resultJWT JWT
	resultJWT.Fill(convertedAPI)

	assert.Equal(t, emptyJWT, resultJWT)
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

func TestBasic(t *testing.T) {
	var emptyBasic Basic

	var convertedAPI apidef.APIDefinition
	emptyBasic.ExtractTo(&convertedAPI)

	var resultBasic Basic
	resultBasic.Fill(convertedAPI)

	assert.Equal(t, emptyBasic, resultBasic)
}

func TestOAuth(t *testing.T) {
	var emptyOAuth OAuth

	var convertedAPI apidef.APIDefinition
	emptyOAuth.ExtractTo(&convertedAPI)

	var resultOAuth OAuth
	resultOAuth.Fill(convertedAPI)

	assert.Equal(t, emptyOAuth, resultOAuth)
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

func TestGoPlugin(t *testing.T) {
	var emptyGoPlugin GoPlugin

	var convertedAPI apidef.APIDefinition
	emptyGoPlugin.ExtractTo(&convertedAPI)

	var resultGoPlugin GoPlugin
	resultGoPlugin.Fill(convertedAPI)

	assert.Equal(t, emptyGoPlugin, resultGoPlugin)
}

func TestCustomPlugin(t *testing.T) {
	var emptyCustomPlugin CustomPlugin

	var convertedAPI apidef.APIDefinition
	emptyCustomPlugin.ExtractTo(&convertedAPI)

	var resultCustomPlugin CustomPlugin
	resultCustomPlugin.Fill(convertedAPI)

	assert.Equal(t, emptyCustomPlugin, resultCustomPlugin)
}
