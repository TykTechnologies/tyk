package oas

import (
	"sort"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGetJWTConfiguration(t *testing.T) {
	t.Run("should retrieve successfully", func(t *testing.T) {
		var api apidef.APIDefinition
		api.EnableJWT = true
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.JWTType: {
				Name:           "jwtAuth",
				AuthHeaderName: "Authorization",
			},
		}

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(api)

		j := oas.GetTykExtension().Server.Authentication.SecuritySchemes["jwtAuth"].(*JWT)
		j.AllowedIssuers = []string{"issuer_one", "issuer_two"}
		j.AllowedAudiences = []string{"audience_one", "audience_two"}
		j.BasePolicyClaims = []string{"policy"}
		j.SubjectClaims = []string{"new_sub"}

		oas.GetTykExtension().Server.Authentication.SecuritySchemes["jwtAuth"] = j
		gotten := oas.GetJWTConfiguration()

		assert.Equal(t, j.AllowedIssuers, gotten.AllowedIssuers)
		assert.Equal(t, []string{"new_sub"}, gotten.SubjectClaims)
		assert.Equal(t, []string{"policy"}, gotten.BasePolicyClaims)
		assert.Equal(t, j.AllowedAudiences, gotten.AllowedAudiences)
	})

	t.Run("should successfully convert identity and policy and return", func(t *testing.T) {
		var api apidef.APIDefinition
		api.EnableJWT = true
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.JWTType: {
				Name:           "jwtAuth",
				AuthHeaderName: "Authorization",
			},
		}
		api.JWTIdentityBaseField = "new_sub"
		api.JWTPolicyFieldName = "policy"

		var oas OAS
		oas.Fill(api)

		j := oas.GetJWTConfiguration()
		assert.Equal(t, j.IdentityBaseField, "new_sub")
		assert.Equal(t, []string{"new_sub"}, j.SubjectClaims)
		assert.Equal(t, j.PolicyFieldName, "policy")
		assert.Equal(t, []string{"policy"}, j.BasePolicyClaims)

		var newAPIDef apidef.APIDefinition
		oas.GetJWTConfiguration().PolicyFieldName = "policy"
		oas.GetJWTConfiguration().IdentityBaseField = "subject"
		oas.ExtractTo(&newAPIDef)

		assert.Equal(t, "policy", newAPIDef.JWTPolicyFieldName)
		assert.Equal(t, "subject", newAPIDef.JWTIdentityBaseField)
	})

	t.Run("should return nil", func(t *testing.T) {
		var auth apidef.AuthConfig
		Fill(t, &auth, 0)
		auth.DisableHeader = false

		var api apidef.APIDefinition
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: auth,
		}

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(api)

		assert.Nil(t, oas.GetJWTConfiguration())
	})
}

func TestOAS_Security(t *testing.T) {
	var auth apidef.AuthConfig
	Fill(t, &auth, 0)
	auth.DisableHeader = false

	var api apidef.APIDefinition // bundle enabled
	api.AuthConfigs = map[string]apidef.AuthConfig{
		apidef.AuthTokenType: auth,
	}

	var oas OAS // bundle enabled true
	oas.SetTykExtension(&XTykAPIGateway{})
	oas.fillSecurity(api)

	var convertedAPI apidef.APIDefinition // bundle enabled
	oas.extractSecurityTo(&convertedAPI)

	convertedAPI.SecurityRequirements = nil
	assert.Equal(t, api, convertedAPI)
}

func TestOAS_ApiKeyScheme(t *testing.T) {
	const (
		authName   = "my-auth"
		headerName = "header-auth"
		queryName  = "query-auth"
		cookieName = "cookie-auth"
	)

	ac := apidef.AuthConfig{
		Name:           authName,
		DisableHeader:  false,
		AuthHeaderName: headerName,
		UseParam:       true,
		ParamName:      queryName,
		UseCookie:      true,
		CookieName:     cookieName,
	}

	check := func(in, name string, ac apidef.AuthConfig, s OAS) {
		if s.Components == nil {
			s.Components = &openapi3.Components{}
		}

		s.fillAPIKeyScheme(&ac)

		expectedAC := ac
		expExtractedAC := apidef.AuthConfig{Name: authName}

		switch in {
		case header:
			expectedAC.AuthHeaderName = ""
			expExtractedAC.AuthHeaderName = name
			expExtractedAC.DisableHeader = false
		case query:
			expectedAC.ParamName = ""
			expExtractedAC.ParamName = name
			expExtractedAC.UseParam = true
		case cookie:
			expectedAC.CookieName = ""
			expExtractedAC.CookieName = name
			expExtractedAC.UseCookie = true
		}

		expSecurity := openapi3.SecurityRequirements{
			{
				authName: []string{},
			},
		}

		expSecuritySchemes := openapi3.SecuritySchemes{
			authName: &openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{
					Type: typeAPIKey,
					In:   in,
					Name: name,
				},
			},
		}

		assert.Equal(t, expSecurity, s.Security)
		assert.Equal(t, expSecuritySchemes, s.Components.SecuritySchemes)
		assert.Equal(t, expectedAC, ac)

		var extractedAC apidef.AuthConfig
		s.extractAPIKeySchemeTo(&extractedAC, authName)

		assert.Equal(t, expExtractedAC, extractedAC)
	}

	t.Run("should not set header name in tyk extension", func(t *testing.T) {
		check(header, headerName, ac, OAS{})
	})

	t.Run("should not set query name in tyk extension", func(t *testing.T) {
		ac.DisableHeader = true
		check(query, queryName, ac, OAS{})
	})

	t.Run("should not set cookie name in tyk extension", func(t *testing.T) {
		ac.DisableHeader = true
		ac.UseParam = false
		check(cookie, cookieName, ac, OAS{})
	})

	testOAS := func(in, name string) (oas OAS) {
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				authName: &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						In:   in,
						Name: name,
					},
				},
			},
		}
		return
	}

	t.Run("already filled scheme in=header value should be respected", func(t *testing.T) {
		ac.DisableHeader = true
		check(header, headerName, ac, testOAS(header, headerName))
	})

	t.Run("already filled scheme in=query value should be respected", func(t *testing.T) {
		ac.DisableHeader = false
		ac.UseParam = false
		check(query, queryName, ac, testOAS(query, queryName))
	})

	t.Run("already filled scheme in=cookie value should be respected", func(t *testing.T) {
		ac.DisableHeader = false
		ac.UseParam = true
		ac.UseCookie = false
		check(cookie, cookieName, ac, testOAS(cookie, cookieName))
	})
}

func TestOAS_Token(t *testing.T) {
	const securityName = "custom"

	oas := OAS{T: openapi3.T{
		Components: &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				securityName: {
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						Name: "x-query",
						In:   query,
					},
				},
			},
		},
		Security: openapi3.SecurityRequirements{
			{
				securityName: []string{},
			},
		},
	}}

	setToken := func(token Token) {
		oas.Extensions = map[string]interface{}{
			ExtensionTykAPIGateway: &XTykAPIGateway{
				Server: Server{
					Authentication: &Authentication{
						SecuritySchemes: SecuritySchemes{
							securityName: &token,
						},
					},
				},
			},
		}
	}

	convertAPI := func() OAS {
		var api apidef.APIDefinition
		api.AuthConfigs = make(map[string]apidef.AuthConfig)
		oas.extractTokenTo(&api, securityName)

		var convertedOAS OAS
		convertedOAS.Components = &openapi3.Components{
			SecuritySchemes: oas.Components.SecuritySchemes,
		}

		convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: SecuritySchemes{}}}})
		convertedOAS.fillToken(api)

		return convertedOAS
	}

	t.Run("enabled", func(t *testing.T) {
		var token Token
		Fill(t, &token, 0)
		token.Query = nil

		setToken(token)
		convertedOAS := convertAPI()

		assert.Equal(t, oas, convertedOAS)
	})

	t.Run("disabled", func(t *testing.T) {
		var token Token
		token.Enabled = getBoolPointer(false)

		setToken(token)
		convertedOAS := convertAPI()

		assert.NotNil(t, convertedOAS.getTykSecuritySchemes()[securityName])
	})

}

func TestOAS_Token_MultipleSecuritySchemes(t *testing.T) {
	const securityName = "custom"
	const securityName2 = "custom2"

	var oas OAS
	oas.Security = openapi3.SecurityRequirements{
		{
			securityName:  []string{},
			securityName2: []string{},
		},
	}

	oas.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type: typeAPIKey,
					Name: "x-query",
					In:   query,
				},
			},
			securityName2: {
				Value: &openapi3.SecurityScheme{
					Type: typeAPIKey,
					Name: "x-header",
					In:   header,
				},
			},
		},
	}

	xTykAPIGateway := &XTykAPIGateway{
		Server: Server{
			Authentication: &Authentication{
				Enabled: true,
				SecuritySchemes: SecuritySchemes{
					securityName: &Token{
						Enabled: getBoolPointer(true),
					},
				},
			},
		},
	}

	oas.SetTykExtension(xTykAPIGateway)

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Fill(api)

	assert.Len(t, convertedOAS.getTykSecuritySchemes(), 1)
	assert.Contains(t, convertedOAS.getTykSecuritySchemes(), securityName)
}

func TestOAS_AppendSecurity(t *testing.T) {
	oas := OAS{}
	oas.Security = openapi3.SecurityRequirements{
		openapi3.SecurityRequirement{
			"one": []string{},
			"two": []string{},
		},
		openapi3.SecurityRequirement{
			"three": []string{},
			"four":  []string{},
		},
	}

	t.Run("append new", func(t *testing.T) {
		oas.appendSecurity("new")

		assert.Len(t, oas.Security[0], 3)
		assert.Contains(t, oas.Security[0], "one")
		assert.Contains(t, oas.Security[0], "two")
		assert.Contains(t, oas.Security[0], "new")

		assert.Len(t, oas.Security[1], 2)
		assert.Contains(t, oas.Security[1], "three")
		assert.Contains(t, oas.Security[1], "four")

		delete(oas.Security[0], "new")
	})

	t.Run("append same", func(t *testing.T) {
		oas.appendSecurity("one")

		assert.Len(t, oas.Security[0], 2)
		assert.Contains(t, oas.Security[0], "one")
		assert.Contains(t, oas.Security[0], "two")

		assert.Len(t, oas.Security[1], 2)
		assert.Contains(t, oas.Security[1], "three")
		assert.Contains(t, oas.Security[1], "four")
	})
}

func TestOAS_JWT(t *testing.T) {
	const securityName = "custom"

	var oas OAS
	oas.Security = openapi3.SecurityRequirements{
		{
			securityName: []string{},
		},
	}

	oas.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type:         typeHTTP,
					Scheme:       schemeBearer,
					BearerFormat: bearerFormatJWT,
				},
			},
		},
	}

	var jwt JWT
	Fill(t, &jwt, 0)
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						securityName: &jwt,
					},
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.extractJWTTo(&api, securityName)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{}
	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: SecuritySchemes{}}}})

	// pre-populate oas only field before testing and make sure it is not modified
	convertedOAS.Security = openapi3.SecurityRequirements{
		{
			securityName: []string{},
		},
	}

	convertedOAS.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type:         typeHTTP,
					Scheme:       schemeBearer,
					BearerFormat: bearerFormatJWT,
				},
			},
		},
	}

	convertedOAS.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						securityName: &JWT{
							CustomClaimValidation: oas.GetJWTConfiguration().CustomClaimValidation,
							JTIValidation: JTIValidation{
								Enabled: oas.GetJWTConfiguration().JTIValidation.Enabled,
							},
							AllowedIssuers:   oas.GetJWTConfiguration().AllowedIssuers,
							AllowedAudiences: oas.GetJWTConfiguration().AllowedAudiences,
							AllowedSubjects:  oas.GetJWTConfiguration().AllowedSubjects,
							SubjectClaims:    oas.GetJWTConfiguration().SubjectClaims,
							BasePolicyClaims: oas.GetJWTConfiguration().BasePolicyClaims,
							Scopes: &Scopes{
								Claims: oas.GetJWTConfiguration().Scopes.Claims,
							},
						},
					},
				},
			},
		},
	}

	convertedOAS.fillJWT(api)

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_Basic(t *testing.T) {
	const securityName = "custom"

	var oas OAS
	oas.Security = openapi3.SecurityRequirements{
		{
			securityName: []string{},
		},
	}

	oas.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type:   typeHTTP,
					Scheme: schemeBasic,
				},
			},
		},
	}

	var basic Basic
	Fill(t, &basic, 0)
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						securityName: &basic,
					},
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.extractBasicTo(&api, securityName)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{}
	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: SecuritySchemes{}}}})
	convertedOAS.fillBasic(api)

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_OAuth(t *testing.T) {
	const securityName = "custom"
	scopes := map[string]string{
		"write:pets": "modify pets in your account",
		"read:pets":  "read your pets",
	}

	var oas OAS
	oas.Paths = openapi3.NewPaths()
	oas.Security = openapi3.SecurityRequirements{
		{
			securityName: []string{},
		},
	}

	oas.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type: typeOAuth2,
					Flows: &openapi3.OAuthFlows{
						AuthorizationCode: &openapi3.OAuthFlow{
							AuthorizationURL: "{api-url}/oauth/authorize",
							TokenURL:         "{api-url}/oauth/token",
							Scopes:           scopes,
						},
						ClientCredentials: &openapi3.OAuthFlow{
							Scopes: scopes,
						},
					},
				},
			},
		},
	}

	var oauth OAuth
	Fill(t, &oauth, 0)
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						securityName: &oauth,
					},
				},
			},
		},
	}

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{SecuritySchemes: oas.Components.SecuritySchemes}
	convertedOAS.Fill(api)
	flows := convertedOAS.Components.SecuritySchemes[securityName].Value.Flows

	assert.Equal(t, flows.AuthorizationCode.AuthorizationURL, "{api-url}/oauth/authorize")
	assert.Equal(t, flows.AuthorizationCode.TokenURL, "{api-url}/oauth/token")
	assert.Equal(t, flows.ClientCredentials.TokenURL, "/oauth/token")

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_ExternalOAuth(t *testing.T) {
	const securityName = "custom"
	scopes := map[string]string{
		"write:pets": "modify pets in your account",
		"read:pets":  "read your pets",
	}

	var oas OAS
	oas.Paths = openapi3.NewPaths()
	oas.Security = openapi3.SecurityRequirements{
		{
			securityName: []string{},
		},
	}

	oas.Components = &openapi3.Components{
		SecuritySchemes: openapi3.SecuritySchemes{
			securityName: {
				Value: &openapi3.SecurityScheme{
					Type: typeOAuth2,
					Flows: &openapi3.OAuthFlows{
						AuthorizationCode: &openapi3.OAuthFlow{
							AuthorizationURL: "{api-url}/oauth/authorize",
							TokenURL:         "{api-url}/oauth/token",
							Scopes:           scopes,
						},
						ClientCredentials: &openapi3.OAuthFlow{
							Scopes: scopes,
						},
					},
				},
			},
		},
	}

	var externalOAuth ExternalOAuth
	Fill(t, &externalOAuth, 0)
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						securityName: &externalOAuth,
					},
				},
			},
		},
	}

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{SecuritySchemes: oas.Components.SecuritySchemes}
	convertedOAS.Fill(api)
	flows := convertedOAS.Components.SecuritySchemes[securityName].Value.Flows

	assert.Equal(t, flows.AuthorizationCode.AuthorizationURL, "{api-url}/oauth/authorize")
	assert.Equal(t, flows.AuthorizationCode.TokenURL, "{api-url}/oauth/token")

	assert.Equal(t, oas, convertedOAS)

	t.Run("when externalOAuthType doesn't exist in AuthConfigs", func(t *testing.T) {
		// Delete externalOAuth config from AuthConfigs map, a sensible default config will be used by
		// OAS.fillExternalOAuth method.
		delete(api.AuthConfigs, apidef.ExternalOAuthType)

		var convertedOASWithoutExternalOAuth OAS
		convertedOASWithoutExternalOAuth.Components = &openapi3.Components{SecuritySchemes: oas.Components.SecuritySchemes}
		convertedOASWithoutExternalOAuth.Fill(api)
		authFlows := convertedOASWithoutExternalOAuth.Components.SecuritySchemes[securityName].Value.Flows
		assert.Equal(t, authFlows.AuthorizationCode.AuthorizationURL, "{api-url}/oauth/authorize")
		assert.Equal(t, authFlows.AuthorizationCode.TokenURL, "{api-url}/oauth/token")
		assert.Equal(t,
			oas.Components.SecuritySchemes[apidef.ExternalOAuthType],
			convertedOASWithoutExternalOAuth.Components.SecuritySchemes[apidef.ExternalOAuthType],
		)
	})
}

func TestOAS_OIDC(t *testing.T) {
	var oas OAS
	var oidc OIDC
	Fill(t, &oidc, 0)
	sort.Slice(oidc.Scopes.ScopeToPolicyMapping, func(i, j int) bool {
		return oidc.Scopes.ScopeToPolicyMapping[i].Scope < oidc.Scopes.ScopeToPolicyMapping[j].Scope
	})

	for _, provider := range oidc.Providers {
		sort.Slice(provider.ClientToPolicyMapping, func(i, j int) bool {
			return provider.ClientToPolicyMapping[i].ClientID < provider.ClientToPolicyMapping[j].ClientID
		})
	}

	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					OIDC: &oidc,
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.getTykAuthentication().ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{}}})
	convertedOAS.getTykAuthentication().Fill(api)

	// set scope claims cause it is OAS only
	convertedOAS.Extensions[ExtensionTykAPIGateway].(*XTykAPIGateway).Server.Authentication.OIDC.Scopes.Claims = oidc.Scopes.Claims
	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_CustomPlugin(t *testing.T) {
	var oas OAS
	var customPlugin CustomPluginAuthentication
	Fill(t, &customPlugin, 0)
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Custom: &customPlugin,
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.getTykAuthentication().ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{}}})
	convertedOAS.getTykAuthentication().Fill(api)

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_TykAuthentication_NoOASSecurity(t *testing.T) {
	var hmac HMAC
	Fill(t, &hmac, 0)

	var oas OAS
	oas.Components = &openapi3.Components{}
	oas.Paths = openapi3.NewPaths()
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					HMAC: &hmac,
				},
			},
		},
	}

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Fill(api)

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_fillSecurity_CentralizedManagement(t *testing.T) {
	t.Run("should manage Security requirements centrally", func(t *testing.T) {
		var api apidef.APIDefinition
		api.UseKeylessAccess = false

		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				Name:           "token-auth",
				AuthHeaderName: "X-API-Key",
			},
		}

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(api)

		assert.NotNil(t, oas.Security)
		assert.Len(t, oas.Security, 1)
		assert.Contains(t, oas.Security[0], "token-auth")
	})

	t.Run("should use explicit SecurityRequirements for OR logic", func(t *testing.T) {
		var api apidef.APIDefinition
		api.UseKeylessAccess = false

		api.SecurityRequirements = [][]string{
			{"token-auth"},
			{"jwt-auth"},
		}

		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				Name:           "token-auth",
				AuthHeaderName: "X-API-Key",
			},
			apidef.JWTType: {
				Name:           "jwt-auth",
				AuthHeaderName: "Authorization",
			},
		}
		api.EnableJWT = true

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(api)

		assert.NotNil(t, oas.Security)
		assert.Len(t, oas.Security, 2, "Should have 2 requirements for OR logic")

		assert.Len(t, oas.Security[0], 1)
		assert.Contains(t, oas.Security[0], "token-auth")

		assert.Len(t, oas.Security[1], 1)
		assert.Contains(t, oas.Security[1], "jwt-auth")
	})

	t.Run("should handle keyless access", func(t *testing.T) {
		var api apidef.APIDefinition
		api.UseKeylessAccess = true

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(api)

		assert.Nil(t, oas.Security)
	})
}

func TestOAS_extractSecurityTo_ORLogic(t *testing.T) {
	t.Run("should extract multiple Security requirements as OR logic", func(t *testing.T) {
		var oas OAS
		oas.Security = openapi3.SecurityRequirements{
			{"token-auth": []string{}},
			{"jwt-auth": []string{}},
		}

		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"token-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						In:   header,
						Name: "X-API-Key",
					},
				},
				"jwt-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		trueVal := true
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"token-auth": &Token{Enabled: &trueVal},
						"jwt-auth":   &JWT{Enabled: true},
					},
				},
			},
		})

		var api apidef.APIDefinition
		oas.extractSecurityTo(&api)

		assert.Len(t, api.SecurityRequirements, 2)
		assert.Equal(t, []string{"token-auth"}, api.SecurityRequirements[0])
		assert.Equal(t, []string{"jwt-auth"}, api.SecurityRequirements[1])
	})

	t.Run("should handle single Security requirement (no OR logic)", func(t *testing.T) {
		var oas OAS
		oas.Security = openapi3.SecurityRequirements{
			{
				"token-auth": []string{},
				"jwt-auth":   []string{},
			},
		}

		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"token-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						In:   header,
						Name: "X-API-Key",
					},
				},
				"jwt-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		trueVal := true
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"token-auth": &Token{Enabled: &trueVal},
						"jwt-auth":   &JWT{Enabled: true},
					},
				},
			},
		})

		var api apidef.APIDefinition
		oas.extractSecurityTo(&api)

		assert.Nil(t, api.SecurityRequirements)
	})

	t.Run("should handle empty Security", func(t *testing.T) {
		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})

		var api apidef.APIDefinition
		oas.extractSecurityTo(&api)

		assert.Nil(t, api.SecurityRequirements)
	})
}

func TestOAS_GetJWTConfiguration_EmptySecurity(t *testing.T) {
	t.Run("should return nil when Security array is nil", func(t *testing.T) {
		var oas OAS
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					},
				},
			},
		})

		oas.Security = nil

		jwt := oas.GetJWTConfiguration()
		assert.Nil(t, jwt)
	})

	t.Run("should return nil when Security array is empty", func(t *testing.T) {
		var oas OAS
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					},
				},
			},
		})

		oas.Security = openapi3.SecurityRequirements{}

		jwt := oas.GetJWTConfiguration()
		assert.Nil(t, jwt)
	})

	t.Run("should return nil when no JWT configuration exists", func(t *testing.T) {
		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{},
				},
			},
		})

		jwt := oas.GetJWTConfiguration()
		assert.Nil(t, jwt)
	})

	t.Run("should return JWT when Security contains JWT reference", func(t *testing.T) {
		var oas OAS
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwt-auth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					},
				},
			},
		})

		oas.Security = openapi3.SecurityRequirements{
			{"jwt-auth": []string{}},
		}

		jwt := oas.GetJWTConfiguration()
		assert.NotNil(t, jwt)
		assert.Equal(t, "header", jwt.Source)
	})
}

func TestOAS_SecurityRequirements_RoundTrip(t *testing.T) {
	t.Run("should round-trip OR logic correctly", func(t *testing.T) {
		var originalAPI apidef.APIDefinition
		originalAPI.UseKeylessAccess = false
		originalAPI.SecurityRequirements = [][]string{
			{"token-auth"},
			{"jwt-auth"},
		}
		originalAPI.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				Name:           "token-auth",
				AuthHeaderName: "X-API-Key",
			},
			apidef.JWTType: {
				Name:           "jwt-auth",
				AuthHeaderName: "Authorization",
			},
		}
		originalAPI.EnableJWT = true

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(originalAPI)

		var extractedAPI apidef.APIDefinition
		oas.extractSecurityTo(&extractedAPI)

		assert.Equal(t, originalAPI.SecurityRequirements, extractedAPI.SecurityRequirements)
	})

	t.Run("should round-trip AND logic correctly", func(t *testing.T) {
		var originalAPI apidef.APIDefinition
		originalAPI.UseKeylessAccess = false
		originalAPI.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				Name:           "token-auth",
				AuthHeaderName: "X-API-Key",
			},
			apidef.JWTType: {
				Name:           "jwt-auth",
				AuthHeaderName: "Authorization",
			},
		}
		originalAPI.EnableJWT = true

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{})
		oas.fillSecurity(originalAPI)

		var extractedAPI apidef.APIDefinition
		oas.extractSecurityTo(&extractedAPI)

		// Single requirement (AND logic) doesn't need explicit SecurityRequirements
		assert.Nil(t, extractedAPI.SecurityRequirements)
	})
}

func TestOAS_fillSecurity_BackwardCompatibility(t *testing.T) {
	t.Run("should maintain backward compatibility with tests calling fill methods directly", func(t *testing.T) {
		var api apidef.APIDefinition
		api.AuthConfigs = map[string]apidef.AuthConfig{
			apidef.AuthTokenType: {
				Name:           "token-auth",
				AuthHeaderName: "X-API-Key",
			},
		}

		var oas OAS
		oas.Components = &openapi3.Components{}
		oas.SetTykExtension(&XTykAPIGateway{})

		ac := api.AuthConfigs[apidef.AuthTokenType]
		oas.fillAPIKeyScheme(&ac)

		assert.NotNil(t, oas.Security)
		assert.Len(t, oas.Security, 1)
		assert.Contains(t, oas.Security[0], "token-auth")

		assert.NotNil(t, oas.Components.SecuritySchemes)
		assert.Contains(t, oas.Components.SecuritySchemes, "token-auth")
	})
}

func TestSecurityRequirementsPreservation(t *testing.T) {
	testCases := []struct {
		name            string
		inputSecurity   openapi3.SecurityRequirements
		mode            string
		expectPreserved bool
	}{
		{
			name: "Two separate OR requirements (user's bug case)",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}},
				{"basicAuth": []string{}},
			},
			mode:            SecurityProcessingModeLegacy,
			expectPreserved: true,
		},
		{
			name: "Single requirement with one scheme",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}},
			},
			mode:            SecurityProcessingModeLegacy,
			expectPreserved: true,
		},
		{
			name: "AND requirements (multiple in one)",
			inputSecurity: openapi3.SecurityRequirements{
				{"authToken": []string{}, "basicAuth": []string{}},
			},
			mode:            SecurityProcessingModeLegacy,
			expectPreserved: true,
		},
		{
			name: "Three separate OR requirements",
			inputSecurity: openapi3.SecurityRequirements{
				{"apiKey": []string{}},
				{"oauth2": []string{"read", "write"}},
				{"jwt": []string{}},
			},
			mode:            SecurityProcessingModeCompliant,
			expectPreserved: true,
		},
		{
			name: "Mixed AND/OR requirements",
			inputSecurity: openapi3.SecurityRequirements{
				{"apiKey": []string{}},
				{"oauth2": []string{"read"}, "jwt": []string{}},
			},
			mode:            SecurityProcessingModeLegacy,
			expectPreserved: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create OAS with the given security requirements
			oasDoc := &openapi3.T{
				OpenAPI: "3.0.3",
				Info: &openapi3.Info{
					Title:   "Security Test",
					Version: "1.0.0",
				},
				Servers: openapi3.Servers{
					&openapi3.Server{URL: "http://localhost:8181/test/"},
				},
				Security: tc.inputSecurity,
				Paths:    openapi3.NewPaths(),
				Components: &openapi3.Components{
					SecuritySchemes: createTestSecuritySchemes(),
				},
			}

			oasWrapper := &OAS{T: *oasDoc}
			tykExt := createTestTykExtension()
			// Set the processing mode in OAS (OAS-only feature)
			if tykExt.Server.Authentication != nil {
				tykExt.Server.Authentication.SecurityProcessingMode = tc.mode
			}
			oasWrapper.SetTykExtension(tykExt)

			// Extract to APIDefinition
			apiDef := &apidef.APIDefinition{}
			oasWrapper.ExtractTo(apiDef)

			// Fill back to new OAS
			resultOAS := &OAS{}
			resultOAS.Fill(*apiDef)

			// Verify preservation
			if tc.expectPreserved {
				assert.Equal(t, len(tc.inputSecurity), len(resultOAS.T.Security),
					"Number of security requirements should be preserved")

				// Check that structure is preserved
				for i, inputReq := range tc.inputSecurity {
					if i < len(resultOAS.T.Security) {
						resultReq := resultOAS.T.Security[i]
						assert.Equal(t, len(inputReq), len(resultReq),
							"Number of schemes in requirement %d should be preserved", i)

						for scheme := range inputReq {
							assert.Contains(t, resultReq, scheme,
								"Scheme %s should be in requirement %d", scheme, i)
						}
					}
				}
			}
		})
	}
}

func createTestSecuritySchemes() openapi3.SecuritySchemes {
	return openapi3.SecuritySchemes{
		"apiKey": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "apiKey",
				In:   "header",
				Name: "X-API-Key",
			},
		},
		"authToken": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "apiKey",
				In:   "header",
				Name: "Authorization",
			},
		},
		"basicAuth": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:   "http",
				Scheme: "basic",
			},
		},
		"oauth2": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type: "oauth2",
				Flows: &openapi3.OAuthFlows{
					AuthorizationCode: &openapi3.OAuthFlow{
						AuthorizationURL: "https://example.com/oauth/authorize",
						TokenURL:         "https://example.com/oauth/token",
						Scopes: map[string]string{
							"read":  "Read access",
							"write": "Write access",
						},
					},
				},
			},
		},
		"jwt": &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			},
		},
	}
}

func createTestTykExtension() *XTykAPIGateway {
	boolTrue := true
	return &XTykAPIGateway{
		Info: Info{
			Name: "test-api",
			State: State{
				Active: true,
			},
		},
		Server: Server{
			ListenPath: ListenPath{
				Value: "/test",
				Strip: true,
			},
			Authentication: &Authentication{
				Enabled: true,
				SecuritySchemes: SecuritySchemes{
					"apiKey": &Token{
						Enabled: &boolTrue,
					},
					"authToken": &Token{
						Enabled: &boolTrue,
					},
					"basicAuth": &Basic{
						Enabled: true,
					},
					"oauth2": &OAuth{
						Enabled: true,
					},
					"jwt": &JWT{
						Enabled: true,
					},
				},
			},
		},
	}
}

func TestIsProprietaryAuth(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		want       bool
	}{
		{
			name:       "HMAC is proprietary",
			authMethod: "hmac",
			want:       true,
		},
		{
			name:       "Custom is proprietary",
			authMethod: "custom",
			want:       true,
		},
		{
			name:       "mTLS is proprietary",
			authMethod: "mtls",
			want:       true,
		},
		{
			name:       "Coprocess is proprietary",
			authMethod: "coprocess",
			want:       true,
		},
		{
			name:       "JWT is not proprietary",
			authMethod: "jwt",
			want:       false,
		},
		{
			name:       "OAuth2 is not proprietary",
			authMethod: "oauth2",
			want:       false,
		},
		{
			name:       "API Key is not proprietary",
			authMethod: "apikey",
			want:       false,
		},
		{
			name:       "Basic auth is not proprietary",
			authMethod: "basic",
			want:       false,
		},
		{
			name:       "Bearer is not proprietary",
			authMethod: "bearer",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProprietaryAuth(tt.authMethod)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCompliantModeSecuritySeparation(t *testing.T) {
	t.Run("compliant mode separates OAS and vendor security", func(t *testing.T) {
		// Create API with mixed security requirements
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwt"},           // Standard OAS
				{"hmac"},          // Proprietary
				{"jwt", "apikey"}, // Mixed
			},
			UseStandardAuth:         true,
			EnableJWT:               true,
			EnableSignatureChecking: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				"jwt": {
					Name:           "jwt",
					AuthHeaderName: "Authorization",
				},
				"apikey": {
					Name:           "apikey",
					AuthHeaderName: "X-API-Key",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: SecuritySchemes{
						"jwt": &JWT{
							Enabled: true,
						},
						"apikey": &Token{
							Enabled: func() *bool { b := true; return &b }(),
						},
						"hmac": &HMAC{
							Enabled: true,
						},
					},
				},
			},
		})

		// Fill security with compliant mode
		oas.fillSecurity(api)

		// Check OAS Security (should only have non-proprietary)
		assert.Len(t, oas.T.Security, 2) // JWT and JWT+apikey requirements

		// First requirement should be jwt only
		assert.Contains(t, oas.T.Security[0], "jwt")
		assert.NotContains(t, oas.T.Security[0], "hmac")

		// Second requirement should have jwt and apikey
		assert.Contains(t, oas.T.Security[1], "jwt")
		assert.Contains(t, oas.T.Security[1], "apikey")

		// Check Vendor Security (should only have proprietary)
		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security)
		assert.Len(t, tykAuth.Security, 1) // hmac requirement only

		// First vendor requirement should be hmac only
		assert.Contains(t, tykAuth.Security[0], "hmac")
	})

	t.Run("compliant mode creates security from schemes when no requirements", func(t *testing.T) {
		api := apidef.APIDefinition{
			// No SecurityRequirements
			UseStandardAuth: true,
			EnableJWT:       true,
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: SecuritySchemes{
						"jwt": &JWT{
							Enabled: true,
						},
						"apikey": &Token{
							Enabled: func() *bool { b := true; return &b }(),
						},
						"hmac": &HMAC{
							Enabled: true,
						},
					},
				},
			},
		})

		// Fill security with compliant mode
		oas.fillSecurity(api)

		// Should create OAS Security from non-proprietary schemes
		assert.Len(t, oas.T.Security, 1)
		secReq := oas.T.Security[0]
		assert.Contains(t, secReq, "jwt")
		assert.Contains(t, secReq, "apikey")
		assert.NotContains(t, secReq, "hmac")

		// Vendor security should be empty since no explicit requirements
		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.Nil(t, tykAuth.Security)
	})

	t.Run("legacy mode keeps traditional behavior", func(t *testing.T) {
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwt"},
				{"hmac"},
				{"apikey"},
			},
			UseStandardAuth:         true,
			EnableJWT:               true,
			EnableSignatureChecking: true,
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeLegacy, // Explicitly set to legacy
				},
			},
		})

		// Fill security with legacy mode
		oas.fillSecurity(api)

		// In legacy mode, all requirements go to OAS Security
		assert.Len(t, oas.T.Security, 3)

		// Check that all requirements are in OAS Security
		var foundJwt, foundHmac, foundApikey bool
		for _, req := range oas.T.Security {
			if _, ok := req["jwt"]; ok {
				foundJwt = true
			}
			if _, ok := req["hmac"]; ok {
				foundHmac = true
			}
			if _, ok := req["apikey"]; ok {
				foundApikey = true
			}
		}
		assert.True(t, foundJwt)
		assert.True(t, foundHmac)
		assert.True(t, foundApikey)

		// Vendor security should not be set in legacy mode
		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.Nil(t, tykAuth.Security)
	})

	t.Run("compliant mode with getTykAuthentication returns processing mode", func(t *testing.T) {
		api := apidef.APIDefinition{}

		oas := OAS{}
		// Test when authentication is nil
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{},
		})

		oas.fillSecurity(api)
		// Should default to legacy when nil
		assert.Len(t, oas.T.Security, 0)

		// Test when authentication exists with compliant mode
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
				},
			},
		})

		// Verify getTykAuthentication returns the authentication object
		auth := oas.getTykAuthentication()
		assert.NotNil(t, auth)
		assert.Equal(t, SecurityProcessingModeCompliant, auth.SecurityProcessingMode)
	})
}
