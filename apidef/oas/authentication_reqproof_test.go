package oas

import (
	"net/http"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-087
// SW-REQ-087:nominal:nominal
// SW-REQ-087:boundary:boundary
// SW-REQ-087:error_handling:negative
// SW-REQ-087:determinism:nominal
func TestAuthenticationReqProof_ModePRMSchemesAndSources(t *testing.T) {
	t.Run("security processing mode validation accepts only supported modes", func(t *testing.T) {
		assert.True(t, ValidateSecurityProcessingMode(""))
		assert.True(t, ValidateSecurityProcessingMode(SecurityProcessingModeLegacy))
		assert.True(t, ValidateSecurityProcessingMode(SecurityProcessingModeCompliant))
		assert.False(t, ValidateSecurityProcessingMode("strict"))
		assert.Equal(t, SecurityProcessingModeLegacy, GetDefaultSecurityProcessingMode())
	})

	t.Run("protected resource metadata validates enabled boundary cases and default path", func(t *testing.T) {
		assert.NoError(t, (*ProtectedResourceMetadata)(nil).Validate(true))
		assert.NoError(t, (&ProtectedResourceMetadata{}).Validate(true))
		assert.Equal(t, DefaultPRMWellKnownPath, (*ProtectedResourceMetadata)(nil).GetWellKnownPath())
		assert.Equal(t, DefaultPRMWellKnownPath, (&ProtectedResourceMetadata{Enabled: true}).GetWellKnownPath())
		assert.Equal(t, "custom/prm", (&ProtectedResourceMetadata{Enabled: true, WellKnownPath: "custom/prm"}).GetWellKnownPath())

		require.EqualError(t, (&ProtectedResourceMetadata{Enabled: true}).Validate(false), "protectedResourceMetadata.resource is required when enabled")
		require.EqualError(t, (&ProtectedResourceMetadata{Enabled: true, Resource: "https://api.example.com"}).Validate(true), "protectedResourceMetadata.authorizationServers must have at least one entry for MCP APIs")
		assert.NoError(t, (&ProtectedResourceMetadata{
			Enabled:              true,
			Resource:             "https://api.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
		}).Validate(true))
	})

	t.Run("security scheme import preserves supported scheme types and rejects unsupported ones", func(t *testing.T) {
		schemes := SecuritySchemes{}
		require.NoError(t, schemes.Import("apiKey", &openapi3.SecurityScheme{Type: typeAPIKey}, true))
		require.NoError(t, schemes.Import("jwt", &openapi3.SecurityScheme{Type: typeHTTP, Scheme: schemeBearer, BearerFormat: bearerFormatJWT}, true))
		require.NoError(t, schemes.Import("basic", &openapi3.SecurityScheme{Type: typeHTTP, Scheme: schemeBasic}, false))
		require.NoError(t, schemes.Import("oauth", &openapi3.SecurityScheme{Type: typeOAuth2}, true))

		token, ok := schemes["apiKey"].(*Token)
		require.True(t, ok)
		require.NotNil(t, token.Enabled)
		assert.True(t, *token.Enabled)
		_, ok = schemes["jwt"].(*JWT)
		assert.True(t, ok)
		_, ok = schemes["basic"].(*Basic)
		assert.True(t, ok)
		_, ok = schemes["oauth"].(*OAuth)
		assert.True(t, ok)
		assert.Equal(t, apidef.AuthToken, schemes.GetBaseIdentityProvider())

		jwtOnly := SecuritySchemes{"jwt": &JWT{}, "oauth": &OAuth{}}
		assert.Equal(t, apidef.JWTClaim, jwtOnly.GetBaseIdentityProvider())
		assert.Equal(t, apidef.AuthTypeEnum(""), SecuritySchemes{"jwt": &JWT{}}.GetBaseIdentityProvider())

		err := schemes.Import("mutualTLS", &openapi3.SecurityScheme{Type: "mutualTLS"}, true)
		require.Error(t, err)
		assert.EqualError(t, err, "unsupported security scheme: mutualTLS")
	})

	t.Run("auth sources and signatures round-trip classic auth config fields", func(t *testing.T) {
		classic := apidef.AuthConfig{
			DisableHeader:     false,
			AuthHeaderName:    "Authorization",
			UseParam:          true,
			ParamName:         "token",
			UseCookie:         true,
			CookieName:        "session",
			ValidateSignature: true,
			Signature: apidef.SignatureConfig{
				Algorithm:        "hmac-sha256",
				Header:           "X-Signature",
				UseParam:         true,
				ParamName:        "sig",
				Secret:           "secret",
				AllowedClockSkew: 15,
				ErrorCode:        http.StatusForbidden,
				ErrorMessage:     "bad signature",
			},
		}

		var sources AuthSources
		sources.Fill(classic)
		assert.Equal(t, &AuthSource{Enabled: true, Name: "Authorization"}, sources.Header)
		assert.Equal(t, &AuthSource{Enabled: true, Name: "token"}, sources.Query)
		assert.Equal(t, &AuthSource{Enabled: true, Name: "session"}, sources.Cookie)

		extracted := apidef.AuthConfig{}
		sources.ExtractTo(&extracted)
		assert.False(t, extracted.DisableHeader)
		assert.Equal(t, "Authorization", extracted.AuthHeaderName)
		assert.True(t, extracted.UseParam)
		assert.Equal(t, "token", extracted.ParamName)
		assert.True(t, extracted.UseCookie)
		assert.Equal(t, "session", extracted.CookieName)

		var sig Signature
		sig.Fill(classic)
		sigExtracted := apidef.AuthConfig{}
		sig.ExtractTo(&sigExtracted)
		assert.Equal(t, classic.ValidateSignature, sigExtracted.ValidateSignature)
		assert.Equal(t, classic.Signature, sigExtracted.Signature)
	})
}

// Verifies: SYS-REQ-104, SW-REQ-087
// SW-REQ-087:nominal:nominal
// SW-REQ-087:boundary:boundary
// SW-REQ-087:error_handling:negative
// SW-REQ-087:determinism:nominal
func TestAuthenticationReqProof_FillExtractAndPluginShapes(t *testing.T) {
	t.Run("aggregate authentication fill and extract preserve local auth helper shapes", func(t *testing.T) {
		api := apidef.APIDefinition{
			UseKeylessAccess:                     false,
			StripAuthData:                        true,
			BaseIdentityProvidedBy:               apidef.JWTClaim,
			SessionLifetime:                      90,
			SessionLifetimeRespectsKeyExpiration: true,
			EnableSignatureChecking:              true,
			HmacAllowedAlgorithms:                []string{"hmac-sha256", "hmac-sha512"},
			HmacAllowedClockSkew:                 20,
			UseOpenID:                            true,
			OpenIDOptions: apidef.OpenIDOptions{
				SegregateByClient: true,
				Providers: []apidef.OIDProviderConfig{
					{Issuer: "issuer-b", ClientIDs: map[string]string{"client-b": "policy-b", "client-a": "policy-a"}},
				},
			},
			Scopes: apidef.Scopes{
				OIDC: apidef.ScopeClaim{
					ScopeClaimName: "scope",
					ScopeToPolicy:  map[string]string{"write": "policy-write", "read": "policy-read"},
				},
			},
			CustomPluginAuthEnabled: true,
			CustomMiddleware: apidef.MiddlewareSection{
				AuthCheck: apidef.MiddlewareDefinition{
					Disabled:       false,
					Name:           "AuthCheck",
					Path:           "/plugins/auth.so",
					RawBodyOnly:    true,
					RequireSession: true,
				},
				IdExtractor: apidef.MiddlewareIdExtractor{
					Disabled:    false,
					ExtractFrom: apidef.HeaderSource,
					ExtractWith: apidef.ValueExtractor,
					ExtractorConfig: map[string]interface{}{
						"header_name": "X-User-ID",
					},
				},
			},
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.AuthTokenType: {UseCertificate: true},
				apidef.HMACType: {
					DisableHeader:  false,
					AuthHeaderName: "X-HMAC",
				},
				apidef.OIDCType: {
					DisableHeader:  false,
					AuthHeaderName: "Authorization",
					UseCookie:      true,
					CookieName:     "oidc",
				},
				apidef.CoprocessType: {
					DisableHeader:  false,
					AuthHeaderName: "X-Custom",
					UseParam:       true,
					ParamName:      "custom_token",
				},
			},
		}

		var auth Authentication
		auth.Fill(api)

		assert.True(t, auth.Enabled)
		assert.True(t, auth.StripAuthorizationData)
		assert.Equal(t, apidef.JWTClaim, auth.BaseIdentityProvider)
		require.NotNil(t, auth.CustomKeyLifetime)
		assert.True(t, auth.CustomKeyLifetime.Enabled)
		assert.Equal(t, ReadableDuration(90*time.Second), auth.CustomKeyLifetime.Value)
		assert.True(t, auth.CustomKeyLifetime.RespectValidity)
		require.NotNil(t, auth.CertificateAuth)
		assert.True(t, auth.CertificateAuth.Enabled)
		require.NotNil(t, auth.HMAC)
		assert.True(t, auth.HMAC.Enabled)
		assert.Equal(t, []string{"hmac-sha256", "hmac-sha512"}, auth.HMAC.AllowedAlgorithms)
		require.NotNil(t, auth.OIDC)
		assert.True(t, auth.OIDC.Enabled)
		require.Len(t, auth.OIDC.Providers, 1)
		assert.Equal(t, []ClientToPolicy{{ClientID: "client-a", PolicyID: "policy-a"}, {ClientID: "client-b", PolicyID: "policy-b"}}, auth.OIDC.Providers[0].ClientToPolicyMapping)
		require.NotNil(t, auth.OIDC.Scopes)
		assert.Equal(t, []ScopeToPolicy{{Scope: "read", PolicyID: "policy-read"}, {Scope: "write", PolicyID: "policy-write"}}, auth.OIDC.Scopes.ScopeToPolicyMapping)
		require.NotNil(t, auth.Custom)
		require.NotNil(t, auth.Custom.Config)
		assert.True(t, auth.Custom.Enabled)
		assert.Equal(t, "AuthCheck", auth.Custom.Config.FunctionName)
		require.NotNil(t, auth.Custom.Config.IDExtractor)
		assert.Equal(t, "X-User-ID", auth.Custom.Config.IDExtractor.Config.HeaderName)

		var extracted apidef.APIDefinition
		auth.ExtractTo(&extracted)
		assert.False(t, extracted.UseKeylessAccess)
		assert.True(t, extracted.StripAuthData)
		assert.Equal(t, apidef.JWTClaim, extracted.BaseIdentityProvidedBy)
		assert.Equal(t, int64(90), extracted.SessionLifetime)
		assert.True(t, extracted.SessionLifetimeRespectsKeyExpiration)
		assert.True(t, extracted.AuthConfigs[apidef.AuthTokenType].UseCertificate)
		assert.True(t, extracted.EnableSignatureChecking)
		assert.Equal(t, []string{"hmac-sha256", "hmac-sha512"}, extracted.HmacAllowedAlgorithms)
		assert.True(t, extracted.UseOpenID)
		assert.True(t, extracted.OpenIDOptions.SegregateByClient)
		assert.Equal(t, "policy-a", extracted.OpenIDOptions.Providers[0].ClientIDs["client-a"])
		assert.Equal(t, "policy-read", extracted.Scopes.OIDC.ScopeToPolicy["read"])
		assert.True(t, extracted.CustomPluginAuthEnabled)
		assert.Equal(t, "AuthCheck", extracted.CustomMiddleware.AuthCheck.Name)
		assert.Equal(t, apidef.HeaderSource, extracted.CustomMiddleware.IdExtractor.ExtractFrom)
	})

	t.Run("custom plugin auth omits empty auth sources and restores nil temporary config", func(t *testing.T) {
		custom := &CustomPluginAuthentication{Enabled: true}
		api := apidef.APIDefinition{}

		custom.ExtractTo(&api)

		assert.True(t, api.CustomPluginAuthEnabled)
		assert.Nil(t, custom.Config)
		assert.Nil(t, api.AuthConfigs)
	})

	t.Run("zero-value authentication extract tolerates nil optional helpers", func(t *testing.T) {
		auth := &Authentication{}
		api := apidef.APIDefinition{}

		require.NotPanics(t, func() {
			auth.ExtractTo(&api)
		})

		assert.True(t, api.UseKeylessAccess)
		assert.Nil(t, auth.CertificateAuth)
		assert.Nil(t, auth.Custom)
		assert.Nil(t, auth.CustomKeyLifetime)
	})

	t.Run("id extractor config maps classic field names in both directions", func(t *testing.T) {
		api := apidef.APIDefinition{CustomMiddleware: apidef.MiddlewareSection{
			IdExtractor: apidef.MiddlewareIdExtractor{
				Disabled:    false,
				ExtractFrom: apidef.BodySource,
				ExtractWith: apidef.RegexExtractor,
				ExtractorConfig: map[string]interface{}{
					"regex_expression":  "user=(\\w+)",
					"regex_match_index": 1,
				},
			},
		}}

		var extractor IDExtractor
		extractor.Fill(api)
		require.NotNil(t, extractor.Config)
		assert.True(t, extractor.Enabled)
		assert.Equal(t, apidef.BodySource, extractor.Source)
		assert.Equal(t, apidef.RegexExtractor, extractor.With)
		assert.Equal(t, "user=(\\w+)", extractor.Config.Regexp)
		assert.Equal(t, 1, extractor.Config.RegexpMatchIndex)

		var extracted apidef.APIDefinition
		extractor.ExtractTo(&extracted)
		assert.False(t, extracted.CustomMiddleware.IdExtractor.Disabled)
		assert.Equal(t, apidef.BodySource, extracted.CustomMiddleware.IdExtractor.ExtractFrom)
		assert.Equal(t, apidef.RegexExtractor, extracted.CustomMiddleware.IdExtractor.ExtractWith)
		assert.Equal(t, "user=(\\w+)", extracted.CustomMiddleware.IdExtractor.ExtractorConfig["regex_expression"])
		assert.Equal(t, float64(1), extracted.CustomMiddleware.IdExtractor.ExtractorConfig["regex_match_index"])
	})
}
