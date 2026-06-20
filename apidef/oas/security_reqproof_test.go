package oas

import (
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

// Verifies: SYS-REQ-104, SW-REQ-092
// SW-REQ-092:nominal:nominal
// SW-REQ-092:boundary:nominal
// SW-REQ-092:error_handling:nominal
// SW-REQ-092:error_handling:negative
// SW-REQ-092:determinism:nominal
func TestSecurityDocumentHelpersPreserveSupportBehavior(t *testing.T) {
	t.Run("leaf import normalize and nested provider helpers preserve local shapes", func(t *testing.T) {
		token := &Token{}
		token.Import(&openapi3.SecurityScheme{Type: typeAPIKey, In: query, Name: "token"}, true)
		require.NotNil(t, token.Enabled)
		assert.True(t, *token.Enabled)
		require.NotNil(t, token.Query)
		assert.True(t, token.Query.Enabled)

		jwt := &JWT{
			BasePolicyClaims: []string{"policy", "other"},
			SubjectClaims:    []string{"subject", "sub"},
			Scopes:           &Scopes{Claims: []string{"scope", "scp"}},
		}
		jwt.Import(true)
		jwt.Normalize()
		assert.True(t, jwt.Enabled)
		assert.Equal(t, "policy", jwt.PolicyFieldName)
		assert.Equal(t, "subject", jwt.IdentityBaseField)
		assert.Equal(t, "scope", jwt.Scopes.ClaimName)
		assert.Equal(t, []string{"primary", "secondary"}, mergeStringFirst("primary", []string{"primary", "secondary"}))
		assert.Equal(t, []string{"secondary"}, mergeStringFirst("", []string{"secondary"}))
		(*JWT)(nil).Normalize()

		basic := &Basic{}
		basic.Import(true)
		assert.True(t, basic.Enabled)
		require.NotNil(t, basic.Header)
		assert.Equal(t, defaultAuthSourceName, basic.Header.Name)

		oauth := &OAuth{}
		oauth.Import(true)
		assert.True(t, oauth.Enabled)
		require.NotNil(t, oauth.Header)
		assert.Equal(t, defaultAuthSourceName, oauth.Header.Name)

		bodyCredsAPI := apidef.APIDefinition{}
		bodyCredsAPI.BasicAuth.ExtractFromBody = true
		bodyCredsAPI.BasicAuth.BodyUserRegexp = `<User>(.*)</User>`
		bodyCredsAPI.BasicAuth.BodyPasswordRegexp = `<Password>(.*)</Password>`
		bodyCreds := &ExtractCredentialsFromBody{}
		bodyCreds.Fill(bodyCredsAPI)
		var extractedBody apidef.APIDefinition
		bodyCreds.ExtractTo(&extractedBody)
		assert.True(t, extractedBody.BasicAuth.ExtractFromBody)
		assert.Equal(t, `<User>(.*)</User>`, extractedBody.BasicAuth.BodyUserRegexp)
		assert.Equal(t, `<Password>(.*)</Password>`, extractedBody.BasicAuth.BodyPasswordRegexp)

		jwtValidation := &JWTValidation{}
		jwtValidation.Fill(apidef.JWTValidation{
			Enabled:                 true,
			SigningMethod:           "rsa",
			Source:                  "jwks",
			IdentityBaseField:       "sub",
			IssuedAtValidationSkew:  1,
			NotBeforeValidationSkew: 2,
			ExpiresAtValidationSkew: 3,
		})
		var extractedJWTValidation apidef.JWTValidation
		jwtValidation.ExtractTo(&extractedJWTValidation)
		assert.True(t, extractedJWTValidation.Enabled)
		assert.Equal(t, "rsa", extractedJWTValidation.SigningMethod)
		assert.Equal(t, uint64(3), extractedJWTValidation.ExpiresAtValidationSkew)

		introspection := &Introspection{}
		introspection.Fill(apidef.Introspection{
			Enabled:           true,
			URL:               "https://issuer.example/introspect",
			ClientID:          "client",
			ClientSecret:      "secret",
			IdentityBaseField: "sub",
			Cache:             apidef.IntrospectionCache{Enabled: true, Timeout: 15},
		})
		var extractedIntrospection apidef.Introspection
		introspection.ExtractTo(&extractedIntrospection)
		assert.True(t, extractedIntrospection.Enabled)
		assert.True(t, extractedIntrospection.Cache.Enabled)
		assert.Equal(t, int64(15), extractedIntrospection.Cache.Timeout)

		notifications := &Notifications{}
		notifications.Fill(apidef.NotificationsManager{
			SharedSecret:      "secret",
			OAuthKeyChangeURL: "https://hooks.example/key",
		})
		var extractedNotifications apidef.NotificationsManager
		notifications.ExtractTo(&extractedNotifications)
		assert.Equal(t, "secret", extractedNotifications.SharedSecret)
		assert.Equal(t, "https://hooks.example/key", extractedNotifications.OAuthKeyChangeURL)
	})

	t.Run("api key schemes preserve header query and cookie source mapping", func(t *testing.T) {
		tests := []struct {
			name      string
			config    apidef.AuthConfig
			expected  string
			extracted func(apidef.AuthConfig) string
		}{
			{
				name:     "header",
				config:   apidef.AuthConfig{Name: "headerAuth", AuthHeaderName: "X-Token"},
				expected: header,
				extracted: func(ac apidef.AuthConfig) string {
					assert.False(t, ac.DisableHeader)
					return ac.AuthHeaderName
				},
			},
			{
				name:     "query",
				config:   apidef.AuthConfig{Name: "queryAuth", DisableHeader: true, UseParam: true, ParamName: "token"},
				expected: query,
				extracted: func(ac apidef.AuthConfig) string {
					assert.True(t, ac.UseParam)
					return ac.ParamName
				},
			},
			{
				name:     "cookie",
				config:   apidef.AuthConfig{Name: "cookieAuth", DisableHeader: true, UseCookie: true, CookieName: "tyk_session"},
				expected: cookie,
				extracted: func(ac apidef.AuthConfig) string {
					assert.True(t, ac.UseCookie)
					return ac.CookieName
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				spec := &OAS{T: openapi3.T{Components: &openapi3.Components{}}}
				config := tt.config
				spec.fillAPIKeyScheme(&config)

				ref := spec.Components.SecuritySchemes[tt.config.Name]
				require.NotNil(t, ref)
				assert.Equal(t, typeAPIKey, ref.Value.Type)
				assert.Equal(t, tt.expected, ref.Value.In)
				assert.NotEmpty(t, ref.Value.Name)
				require.Len(t, spec.Security, 1)
				assert.Contains(t, spec.Security[0], tt.config.Name)

				var extracted apidef.AuthConfig
				spec.extractAPIKeySchemeTo(&extracted, tt.config.Name)
				assert.Equal(t, ref.Value.Name, tt.extracted(extracted))
			})
		}
	})

	t.Run("oauth schemes preserve default flows and extraction", func(t *testing.T) {
		spec := &OAS{T: openapi3.T{Components: &openapi3.Components{}}}
		spec.fillOAuthScheme([]osin.AccessRequestType{
			osin.AUTHORIZATION_CODE,
			osin.CLIENT_CREDENTIALS,
			osin.PASSWORD,
			osin.IMPLICIT,
		}, "oauth")

		ref := spec.Components.SecuritySchemes["oauth"]
		require.NotNil(t, ref)
		require.NotNil(t, ref.Value.Flows.AuthorizationCode)
		require.NotNil(t, ref.Value.Flows.ClientCredentials)
		require.NotNil(t, ref.Value.Flows.Password)
		require.NotNil(t, ref.Value.Flows.Implicit)
		assert.Equal(t, "/oauth/authorize", ref.Value.Flows.AuthorizationCode.AuthorizationURL)
		assert.Equal(t, "/oauth/token", ref.Value.Flows.ClientCredentials.TokenURL)
		assert.NotNil(t, ref.Value.Flows.Password.Scopes)

		var api apidef.APIDefinition
		spec.extractOAuthSchemeTo(&api, "oauth")
		assert.ElementsMatch(t, []osin.AccessRequestType{
			osin.AUTHORIZATION_CODE,
			osin.CLIENT_CREDENTIALS,
			osin.PASSWORD,
			osin.IMPLICIT,
		}, api.Oauth2Meta.AllowedAccessTypes)

		externalSpec := &OAS{T: openapi3.T{Components: &openapi3.Components{}}}
		externalSpec.fillOAuthSchemeForExternal("external")
		require.NotNil(t, externalSpec.Components.SecuritySchemes["external"].Value.Flows.AuthorizationCode)
		assert.Equal(t, "/oauth/token", externalSpec.Components.SecuritySchemes["external"].Value.Flows.AuthorizationCode.TokenURL)
	})

	t.Run("proprietary and mixed vendor security helpers classify without duplicating requirements", func(t *testing.T) {
		spec := &OAS{
			T: openapi3.T{
				Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{
					"jwt": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					}},
				}},
				Security: openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"jwt": []string{}},
					openapi3.SecurityRequirement{"basic": []string{}},
				},
			},
		}
		spec.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{
			SecurityProcessingMode: SecurityProcessingModeCompliant,
			Security:               [][]string{{"hmac", "jwt"}, {"custom"}},
			SecuritySchemes: SecuritySchemes{
				"jwt":    &JWT{Enabled: true},
				"hmac":   &HMAC{Enabled: true},
				"custom": &CustomPluginAuthentication{Enabled: true},
				"token":  &Token{},
			},
		}}})

		assert.True(t, isProprietaryAuth("hmac"))
		assert.False(t, isProprietaryAuth("jwt"))
		assert.True(t, spec.isProprietaryAuthScheme("hmac"))
		assert.False(t, spec.isProprietaryAuthScheme("jwt"))
		assert.True(t, spec.isProprietaryInSecuritySchemes("custom", spec.getTykAuthentication()))
		assert.False(t, spec.isProprietaryInSecuritySchemes("token", spec.getTykAuthentication()))
		assert.True(t, spec.isProprietarySchemeType(map[string]interface{}{"enabled": true}))
		assert.True(t, spec.isInVendorSecurity("jwt", spec.getTykAuthentication()))
		assert.True(t, spec.isInOASComponents("jwt"))
		assert.False(t, spec.isInOASComponents("missing"))

		mixed := spec.identifyMixedVendorAuthSchemes()
		assert.Equal(t, map[string]bool{"jwt": true}, mixed)

		var requirements [][]string
		spec.appendFilteredOASSecurityRequirements(&requirements, mixed)
		assert.Equal(t, [][]string{{"basic"}}, requirements)
		spec.appendVendorSecurityRequirements(&requirements)
		assert.Equal(t, [][]string{{"basic"}, {"hmac", "jwt"}, {"custom"}}, requirements)
	})

	t.Run("security fill and extract coordinate standard schemes without runtime claims", func(t *testing.T) {
		cacheTimeout := tyktime.ReadableDuration(30 * time.Second)
		api := apidef.APIDefinition{
			UseStandardAuth: true,
			EnableJWT:       true,
			UseBasicAuth:    true,
			UseOauth2:       true,
			JWTSource:       "jwks",
			JWTJwksURIs:     []apidef.JWK{{URL: "https://issuer.example/jwks", CacheTimeout: cacheTimeout}},
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.AuthTokenType: {Name: "token", AuthHeaderName: "X-Token"},
				apidef.JWTType:       {Name: "jwt", AuthHeaderName: "Authorization"},
				apidef.BasicType:     {Name: "basic", AuthHeaderName: "Authorization"},
				apidef.OAuthType:     {Name: "oauth", AuthHeaderName: "Authorization"},
			},
		}
		api.BasicAuth.DisableCaching = true
		api.BasicAuth.CacheTTL = 60
		api.BasicAuth.ExtractFromBody = true
		api.BasicAuth.BodyUserRegexp = `<User>(.*)</User>`
		api.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{osin.REFRESH_TOKEN, osin.CLIENT_CREDENTIALS}
		api.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{osin.CODE}
		api.Oauth2Meta.AuthorizeLoginRedirect = "https://login.example/callback"

		spec := &OAS{}
		spec.SetTykExtension(&XTykAPIGateway{})
		spec.fillSecurity(api)

		schemes := spec.getTykSecuritySchemes()
		require.IsType(t, &Token{}, schemes["token"])
		require.IsType(t, &JWT{}, schemes["jwt"])
		require.IsType(t, &Basic{}, schemes["basic"])
		require.IsType(t, &OAuth{}, schemes["oauth"])
		require.Contains(t, spec.Components.SecuritySchemes, "token")
		require.Contains(t, spec.Components.SecuritySchemes, "jwt")
		require.Contains(t, spec.Components.SecuritySchemes, "basic")
		require.Contains(t, spec.Components.SecuritySchemes, "oauth")

		var extracted apidef.APIDefinition
		spec.extractSecurityTo(&extracted)
		assert.True(t, extracted.UseStandardAuth)
		assert.True(t, extracted.EnableJWT)
		assert.True(t, extracted.UseBasicAuth)
		assert.True(t, extracted.UseOauth2)
		assert.Equal(t, "token", extracted.AuthConfigs[apidef.AuthTokenType].Name)
		assert.Equal(t, "jwt", extracted.AuthConfigs[apidef.JWTType].Name)
		assert.Equal(t, "basic", extracted.AuthConfigs[apidef.BasicType].Name)
		assert.Equal(t, "oauth", extracted.AuthConfigs[apidef.OAuthType].Name)
		assert.Equal(t, "jwks", extracted.JWTSource)
		assert.Equal(t, cacheTimeout, extracted.JWTJwksURIs[0].CacheTimeout)
		assert.True(t, extracted.BasicAuth.DisableCaching)
		assert.True(t, extracted.BasicAuth.ExtractFromBody)
		var extractedAccessTypes []string
		for _, accessType := range extracted.Oauth2Meta.AllowedAccessTypes {
			extractedAccessTypes = append(extractedAccessTypes, string(accessType))
		}
		assert.Contains(t, extractedAccessTypes, string(osin.REFRESH_TOKEN))
	})

	t.Run("jwt configuration lookup respects legacy and compliant security selection", func(t *testing.T) {
		newSpec := func(processingMode string) *OAS {
			spec := &OAS{T: openapi3.T{
				Components: &openapi3.Components{SecuritySchemes: openapi3.SecuritySchemes{
					"jwt": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					}},
					"basic": &openapi3.SecuritySchemeRef{Value: &openapi3.SecurityScheme{
						Type:   typeHTTP,
						Scheme: schemeBasic,
					}},
				}},
			}}
			spec.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{
				SecurityProcessingMode: processingMode,
				SecuritySchemes: SecuritySchemes{
					"jwt":   &JWT{Enabled: true, Source: "jwks"},
					"basic": &Basic{Enabled: true},
				},
			}}})
			return spec
		}

		tests := []struct {
			name           string
			spec           *OAS
			security       openapi3.SecurityRequirements
			vendorSecurity [][]string
			wantJWT        bool
		}{
			{
				name: "legacy ignores non-first jwt security",
				spec: newSpec(SecurityProcessingModeLegacy),
				security: openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"basic": []string{}},
					openapi3.SecurityRequirement{"jwt": []string{}},
				},
			},
			{
				name: "legacy accepts first jwt security",
				spec: newSpec(SecurityProcessingModeLegacy),
				security: openapi3.SecurityRequirements{
					openapi3.SecurityRequirement{"jwt": []string{}},
				},
				wantJWT: true,
			},
			{
				name:           "compliant accepts vendor jwt security",
				spec:           newSpec(SecurityProcessingModeCompliant),
				vendorSecurity: [][]string{{"jwt"}},
				wantJWT:        true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				tt.spec.Security = tt.security
				tt.spec.getTykAuthentication().Security = tt.vendorSecurity
				jwtConfig := tt.spec.GetJWTConfiguration()
				if tt.wantJWT {
					require.NotNil(t, jwtConfig)
					assert.Equal(t, "jwks", jwtConfig.Source)
				} else {
					assert.Nil(t, jwtConfig)
				}
			})
		}
	})

	t.Run("reset clears classic security fields before extraction", func(t *testing.T) {
		api := &apidef.APIDefinition{
			UseOauth2:               true,
			UseBasicAuth:            true,
			EnableJWT:               true,
			UseStandardAuth:         true,
			EnableSignatureChecking: true,
			CustomPluginAuthEnabled: true,
			AuthConfigs:             map[string]apidef.AuthConfig{apidef.AuthTokenType: {Name: "token"}},
			JWTSource:               "jwks",
			JWTDefaultPolicies:      []string{"policy"},
		}
		api.BasicAuth.DisableCaching = true
		api.BasicAuth.CacheTTL = 10
		api.BasicAuth.ExtractFromBody = true
		api.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{osin.AUTHORIZATION_CODE}
		api.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{osin.CODE}
		api.Oauth2Meta.AuthorizeLoginRedirect = "https://login.example"

		resetSecuritySchemes(api)
		assert.Nil(t, api.AuthConfigs)
		assert.False(t, api.UseOauth2)
		assert.False(t, api.UseBasicAuth)
		assert.False(t, api.EnableJWT)
		assert.False(t, api.UseStandardAuth)
		assert.False(t, api.EnableSignatureChecking)
		assert.False(t, api.CustomPluginAuthEnabled)
		assert.Empty(t, api.JWTSource)
		assert.Empty(t, api.JWTDefaultPolicies)
		assert.False(t, api.BasicAuth.DisableCaching)
		assert.Empty(t, api.Oauth2Meta.AllowedAccessTypes)
	})
}
