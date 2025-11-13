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

		scheme, _ := oas.GetTykExtension().Server.Authentication.SecuritySchemes.Get("jwtAuth")
		j := scheme.(*JWT)
		j.AllowedIssuers = []string{"issuer_one", "issuer_two"}
		j.AllowedAudiences = []string{"audience_one", "audience_two"}
		j.BasePolicyClaims = []string{"policy"}
		j.SubjectClaims = []string{"new_sub"}

		oas.GetTykExtension().Server.Authentication.SecuritySchemes.Set("jwtAuth", j)
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
						SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
							securityName: &token,
						}),
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

		convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{})}}})
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

		ss, _ := convertedOAS.getTykSecuritySchemes().Get(securityName)
		assert.NotNil(t, ss)
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
				SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
					securityName: &Token{
						Enabled: getBoolPointer(true),
					},
				}),
			},
		},
	}

	oas.SetTykExtension(xTykAPIGateway)

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Fill(api)

	ss := convertedOAS.getTykSecuritySchemes()

	if got := ss.Len(); got != 1 {
		t.Fatalf("expected 1 scheme, got %d", got)
	}

	if _, ok := ss.Get(securityName); !ok {
		t.Fatalf("expected scheme %q to be present", securityName)
	}
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						securityName: &jwt,
					}),
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.extractJWTTo(&api, securityName)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{}
	convertedOAS.SetTykExtension(
		&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{}),
				},
			},
		})

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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
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
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						securityName: &basic,
					}),
				},
			},
		},
	}

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.extractBasicTo(&api, securityName)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{}
	convertedOAS.SetTykExtension(&XTykAPIGateway{
		Server: Server{
			Authentication: &Authentication{
				SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{}),
			},
		},
	})
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						securityName: &oauth,
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						securityName: &externalOAuth,
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"token-auth": &Token{Enabled: &trueVal},
						"jwt-auth":   &JWT{Enabled: true},
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"token-auth": &Token{Enabled: &trueVal},
						"jwt-auth":   &JWT{Enabled: true},
					}),
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

func TestOAS_extractSecurityTo_VendorExtensionSecurity(t *testing.T) {
	t.Run("should extract JWT from vendor extension security in compliant mode", func(t *testing.T) {
		var oas OAS

		// OAS-level security has authToken and jwtAuth as separate OR requirements
		oas.Security = openapi3.SecurityRequirements{
			{"authToken": []string{}},
			{"jwtAuth": []string{}},
		}

		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"authToken": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						In:   header,
						Name: "AuthToken",
					},
				},
				"jwtAuth": &openapi3.SecuritySchemeRef{
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
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"authToken": &Token{Enabled: &trueVal},
						"jwtAuth": &JWT{
							Enabled:           true,
							SigningMethod:     "hmac",
							Source:            "c29tZXRoaW5n",
							IdentityBaseField: "sub",
							SubjectClaims:     []string{"sub"},
							DefaultPolicies:   []string{},
							BasePolicyClaims:  []string{},
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
									Name:    "JWT",
								},
							},
						},
					}),
					HMAC: &HMAC{
						Enabled:           true,
						AllowedAlgorithms: []string{"hmac-sha256"},
						AllowedClockSkew:  -1,
						AuthSources: AuthSources{
							Header: &AuthSource{
								Enabled: true,
								Name:    "HMAC",
							},
						},
					},
					// Vendor extension security: [hmac, jwtAuth] as AND requirement
					Security: [][]string{
						{"hmac", "jwtAuth"},
					},
				},
			},
		})

		var api apidef.APIDefinition
		oas.extractSecurityTo(&api)

		// Verify JWT is enabled
		assert.True(t, api.EnableJWT, "JWT should be enabled")

		// Verify JWT auth config is created
		jwtConfig, ok := api.AuthConfigs[apidef.JWTType]
		assert.True(t, ok, "JWT auth config should exist in auth_configs")
		assert.Equal(t, "jwtAuth", jwtConfig.Name)

		// Verify JWT settings are extracted
		assert.Equal(t, "hmac", api.JWTSigningMethod)
		assert.Equal(t, "c29tZXRoaW5n", api.JWTSource)
		assert.Equal(t, "sub", api.JWTIdentityBaseField)

		// Verify HMAC is also enabled
		assert.True(t, api.EnableSignatureChecking, "HMAC should be enabled")
		hmacConfig, ok := api.AuthConfigs[apidef.HMACType]
		assert.True(t, ok, "HMAC auth config should exist in auth_configs")
		assert.Equal(t, "HMAC", hmacConfig.AuthHeaderName)
		assert.Equal(t, []string{"hmac-sha256"}, api.HmacAllowedAlgorithms)
		assert.Equal(t, float64(-1), api.HmacAllowedClockSkew)

		// Verify authToken is also configured
		tokenConfig, ok := api.AuthConfigs[apidef.AuthTokenType]
		assert.True(t, ok, "Token auth config should exist in auth_configs")
		assert.Equal(t, "authToken", tokenConfig.Name)
		assert.True(t, api.UseStandardAuth, "Standard auth should be enabled")

		// Verify security requirements include both OAS and vendor security
		assert.Len(t, api.SecurityRequirements, 2, "Should have 2 security requirements")
		assert.Contains(t, api.SecurityRequirements, []string{"authToken"})
		assert.Contains(t, api.SecurityRequirements, []string{"hmac", "jwtAuth"})
	})

	t.Run("should keep mixed auth requirement in vendor security when filling OAS", func(t *testing.T) {
		var api apidef.APIDefinition
		api.SecurityRequirements = [][]string{
			{"authToken"},       // Pure OAS auth
			{"hmac", "jwtAuth"}, // Mixed: proprietary + standard
		}

		var oas OAS
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeCompliant,
				},
			},
		})

		oas.fillSecurity(api)

		// Verify OAS security only has pure standard auth
		assert.Len(t, oas.Security, 1, "OAS security should only have standard auth requirements")
		assert.Contains(t, oas.Security[0], "authToken")
		assert.NotContains(t, oas.Security[0], "jwtAuth", "jwtAuth should NOT be in OAS security when part of mixed requirement")

		// Verify vendor security has the mixed requirement
		tykAuth := oas.getTykAuthentication()
		assert.NotNil(t, tykAuth)
		assert.Len(t, tykAuth.Security, 1, "Vendor security should have the mixed requirement")
		assert.Equal(t, []string{"hmac", "jwtAuth"}, tykAuth.Security[0])
	})
}

func TestOAS_GetJWTConfiguration_VendorSecurity(t *testing.T) {
	t.Run("should return JWT config from vendor security in compliant mode", func(t *testing.T) {
		var oas OAS

		// OAS security only has authToken, JWT is in vendor security
		oas.Security = openapi3.SecurityRequirements{
			{"authToken": []string{}},
		}

		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"authToken": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: typeAPIKey,
						In:   header,
						Name: "AuthToken",
					},
				},
				"jwtAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}

		expectedJWT := &JWT{
			Enabled:       true,
			Source:        "test-source",
			SigningMethod: "hmac",
		}

		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": expectedJWT,
					}),
					Security: [][]string{
						{"hmac", "jwtAuth"}, // JWT is in vendor security with HMAC
					},
				},
			},
		})

		jwt := oas.GetJWTConfiguration()
		assert.NotNil(t, jwt, "Should find JWT config in vendor security")
		assert.Equal(t, expectedJWT, jwt)
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt-auth": &JWT{
							Enabled: true,
							Source:  "header",
						},
					}),
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
				SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
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
				}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt": &JWT{
							Enabled: true,
						},
						"apikey": &Token{
							Enabled: func() *bool { b := true; return &b }(),
						},
						"hmac": &HMAC{
							Enabled: true,
						},
					}),
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
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt": &JWT{
							Enabled: true,
						},
						"apikey": &Token{
							Enabled: func() *bool { b := true; return &b }(),
						},
						"hmac": &HMAC{
							Enabled: true,
						},
					}),
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

	t.Run("legacy mode filters proprietary auth", func(t *testing.T) {
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
					SecurityProcessingMode: SecurityProcessingModeLegacy,
				},
			},
		})

		// Fill security with legacy mode
		oas.fillSecurity(api)

		// In legacy mode, only NON-PROPRIETARY auth goes to OAS Security
		// Proprietary auth (hmac) should go to vendor security even in legacy mode
		assert.Len(t, oas.T.Security, 2) // jwt and apikey only

		// Check that non-proprietary requirements are in OAS Security
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
		assert.True(t, foundJwt, "jwt should be in OAS security")
		assert.False(t, foundHmac, "hmac should NOT be in OAS security")
		assert.True(t, foundApikey, "apikey should be in OAS security")

		// Proprietary auth (hmac) should be in vendor security
		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should contain proprietary auth")
		assert.Len(t, tykAuth.Security, 1, "should have 1 proprietary requirement")
		assert.Contains(t, tykAuth.Security[0], "hmac", "hmac should be in vendor security")
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

// TestGetJWTConfiguration_ORAuthentication tests GetJWTConfiguration with OR authentication scenarios
// This test ensures that the JWT configuration is correctly retrieved based on the security processing mode
// and prevents regression of the panic issue when JWT is not the first security requirement.
func TestGetJWTConfiguration_ORAuthentication(t *testing.T) {
	// Helper function to create test OAS with JWT as second security requirement
	createTestOAS := func(processingMode string) *OAS {
		oas := &OAS{}
		oas.T = openapi3.T{
			OpenAPI: "3.0.3",
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"apiKeyAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
					"jwtAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         typeHTTP,
							Scheme:       schemeBearer,
							BearerFormat: bearerFormatJWT,
						},
					},
					"basicAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:   typeHTTP,
							Scheme: "basic",
						},
					},
				},
			},
			// IMPORTANT: JWT is second in the security requirements (API key is first)
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"apiKeyAuth": []string{}},
				openapi3.SecurityRequirement{"jwtAuth": []string{}},
			},
		}

		// Set up Tyk extension with JWT configuration
		tykExtension := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: processingMode,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"apiKeyAuth": &Token{
							Enabled: func() *bool { b := true; return &b }(),
						},
						"jwtAuth": &JWT{
							Enabled:           true,
							SigningMethod:     "hmac",
							Source:            "YS1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc=",
							IdentityBaseField: "sub",
							PolicyFieldName:   "policy",
							AllowedIssuers:    []string{"test-issuer"},
							AllowedAudiences:  []string{"test-audience"},
							JTIValidation: JTIValidation{
								Enabled: false,
							},
						},
					}),
				},
			},
		}
		oas.SetTykExtension(tykExtension)
		return oas
	}

	t.Run("Legacy mode - should NOT find JWT when it's not first", func(t *testing.T) {
		oas := createTestOAS(SecurityProcessingModeLegacy)

		jwtConfig := oas.GetJWTConfiguration()
		assert.Nil(t, jwtConfig, "In legacy mode, JWT should NOT be found when it's not the first security requirement")
	})

	t.Run("Compliant mode - should find JWT even when it's not first", func(t *testing.T) {
		oas := createTestOAS(SecurityProcessingModeCompliant)

		jwtConfig := oas.GetJWTConfiguration()
		assert.NotNil(t, jwtConfig, "In compliant mode, JWT should be found even when it's not the first security requirement")
		assert.Equal(t, "hmac", jwtConfig.SigningMethod)
		assert.Equal(t, "sub", jwtConfig.IdentityBaseField)
		assert.Equal(t, "policy", jwtConfig.PolicyFieldName)
		assert.Equal(t, []string{"test-issuer"}, jwtConfig.AllowedIssuers)
		assert.Equal(t, []string{"test-audience"}, jwtConfig.AllowedAudiences)
	})

	t.Run("Default (empty) mode - should use legacy behavior", func(t *testing.T) {
		oas := createTestOAS("")

		jwtConfig := oas.GetJWTConfiguration()
		assert.Nil(t, jwtConfig, "With empty/default mode, should behave like legacy mode")
	})

	t.Run("Legacy mode - should find JWT when it's first", func(t *testing.T) {
		oas := &OAS{}
		oas.T = openapi3.T{
			OpenAPI: "3.0.3",
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"jwtAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         typeHTTP,
							Scheme:       schemeBearer,
							BearerFormat: bearerFormatJWT,
						},
					},
					"apiKeyAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
				},
			},
			// JWT is first this time
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"jwtAuth": []string{}},
				openapi3.SecurityRequirement{"apiKeyAuth": []string{}},
			},
		}

		tykExtension := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeLegacy,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled:       true,
							SigningMethod: "rsa",
							Source:        "cHVibGljLWtleQ==",
						},
					}),
				},
			},
		}
		oas.SetTykExtension(tykExtension)

		jwtConfig := oas.GetJWTConfiguration()
		assert.NotNil(t, jwtConfig, "Legacy mode should find JWT when it's the first security requirement")
		assert.Equal(t, "rsa", jwtConfig.SigningMethod)
	})

	t.Run("Compliant mode - JWT as third requirement", func(t *testing.T) {
		oas := &OAS{}
		oas.T = openapi3.T{
			OpenAPI: "3.0.3",
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"basicAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:   typeHTTP,
							Scheme: "basic",
						},
					},
					"apiKeyAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
					"jwtAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         typeHTTP,
							Scheme:       schemeBearer,
							BearerFormat: bearerFormatJWT,
						},
					},
				},
			},
			// JWT is third in the list
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"basicAuth": []string{}},
				openapi3.SecurityRequirement{"apiKeyAuth": []string{}},
				openapi3.SecurityRequirement{"jwtAuth": []string{}},
			},
		}

		tykExtension := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled:       true,
							SigningMethod: "ecdsa",
							Source:        "ZWNkc2Eta2V5",
						},
					}),
				},
			},
		}
		oas.SetTykExtension(tykExtension)

		jwtConfig := oas.GetJWTConfiguration()
		assert.NotNil(t, jwtConfig, "Compliant mode should find JWT regardless of its position")
		assert.Equal(t, "ecdsa", jwtConfig.SigningMethod)
	})

	t.Run("No JWT in security requirements - both modes return nil", func(t *testing.T) {
		for _, mode := range []string{SecurityProcessingModeLegacy, SecurityProcessingModeCompliant} {
			t.Run(mode, func(t *testing.T) {
				oas := &OAS{}
				oas.T = openapi3.T{
					OpenAPI: "3.0.3",
					Components: &openapi3.Components{
						SecuritySchemes: openapi3.SecuritySchemes{
							"apiKeyAuth": &openapi3.SecuritySchemeRef{
								Value: &openapi3.SecurityScheme{
									Type: "apiKey",
									In:   "header",
									Name: "X-API-Key",
								},
							},
							"basicAuth": &openapi3.SecuritySchemeRef{
								Value: &openapi3.SecurityScheme{
									Type:   typeHTTP,
									Scheme: "basic",
								},
							},
						},
					},
					Security: openapi3.SecurityRequirements{
						openapi3.SecurityRequirement{"apiKeyAuth": []string{}},
						openapi3.SecurityRequirement{"basicAuth": []string{}},
					},
				}

				tykExtension := &XTykAPIGateway{
					Server: Server{
						Authentication: &Authentication{
							SecurityProcessingMode: mode,
							SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
								"apiKeyAuth": &Token{
									Enabled: func() *bool { b := true; return &b }(),
								},
							}),
						},
					},
				}
				oas.SetTykExtension(tykExtension)

				jwtConfig := oas.GetJWTConfiguration()
				assert.Nil(t, jwtConfig, "Should return nil when no JWT security scheme exists")
			})
		}
	})

	t.Run("JWT with wrong type - both modes return nil", func(t *testing.T) {
		oas := &OAS{}
		oas.T = openapi3.T{
			OpenAPI: "3.0.3",
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"wrongJWT": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:   typeHTTP,
							Scheme: "bearer", // Missing BearerFormat: "JWT"
						},
					},
				},
			},
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"wrongJWT": []string{}},
			},
		}

		tykExtension := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"wrongJWT": &JWT{
							Enabled: true,
						},
					}),
				},
			},
		}
		oas.SetTykExtension(tykExtension)

		jwtConfig := oas.GetJWTConfiguration()
		assert.Nil(t, jwtConfig, "Should return nil when security scheme is not properly typed as JWT")
	})

	t.Run("Empty Security array - both modes return nil", func(t *testing.T) {
		for _, mode := range []string{SecurityProcessingModeLegacy, SecurityProcessingModeCompliant} {
			t.Run(mode, func(t *testing.T) {
				oas := &OAS{}
				oas.T = openapi3.T{
					OpenAPI: "3.0.3",
					Components: &openapi3.Components{
						SecuritySchemes: openapi3.SecuritySchemes{
							"jwtAuth": &openapi3.SecuritySchemeRef{
								Value: &openapi3.SecurityScheme{
									Type:         typeHTTP,
									Scheme:       schemeBearer,
									BearerFormat: bearerFormatJWT,
								},
							},
						},
					},
					Security: openapi3.SecurityRequirements{}, // Empty security requirements
				}

				tykExtension := &XTykAPIGateway{
					Server: Server{
						Authentication: &Authentication{
							SecurityProcessingMode: mode,
							SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
								"jwtAuth": &JWT{
									Enabled: true,
								},
							}),
						},
					},
				}
				oas.SetTykExtension(tykExtension)

				jwtConfig := oas.GetJWTConfiguration()
				assert.Nil(t, jwtConfig, "Should return nil when Security array is empty")
			})
		}
	})

	t.Run("Nil getTykAuthentication - defaults to legacy mode", func(t *testing.T) {
		oas := &OAS{}
		oas.T = openapi3.T{
			OpenAPI: "3.0.3",
			Components: &openapi3.Components{
				SecuritySchemes: openapi3.SecuritySchemes{
					"apiKeyAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type: "apiKey",
							In:   "header",
							Name: "X-API-Key",
						},
					},
					"jwtAuth": &openapi3.SecuritySchemeRef{
						Value: &openapi3.SecurityScheme{
							Type:         typeHTTP,
							Scheme:       schemeBearer,
							BearerFormat: bearerFormatJWT,
						},
					},
				},
			},
			Security: openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{"apiKeyAuth": []string{}},
				openapi3.SecurityRequirement{"jwtAuth": []string{}}, // JWT is second
			},
		}

		// No Tyk extension set - should default to legacy mode
		jwtConfig := oas.GetJWTConfiguration()
		assert.Nil(t, jwtConfig, "Should behave as legacy mode when getTykAuthentication is nil")
	})
}

func TestIsProprietaryAuthScheme(t *testing.T) {
	t.Run("should identify known proprietary type names", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{},
			},
		})

		assert.True(t, oas.isProprietaryAuthScheme("hmac"), "hmac should be proprietary")
		assert.True(t, oas.isProprietaryAuthScheme("custom"), "custom should be proprietary")
		assert.True(t, oas.isProprietaryAuthScheme("mtls"), "mtls should be proprietary")
		assert.True(t, oas.isProprietaryAuthScheme("coprocess"), "coprocess should be proprietary")
	})

	t.Run("should identify scheme in vendor security as proprietary when not in OAS Components", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Security: [][]string{
						{"customAuth"},
					},
				},
			},
		})

		assert.True(t, oas.isProprietaryAuthScheme("customAuth"), "customAuth in vendor security should be proprietary")
	})

	t.Run("should identify scheme in vendor security and OAS Components by SecuritySchemes type", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwtAuth": &openapi3.SecuritySchemeRef{
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
					Security: [][]string{
						{"jwtAuth"},
					},
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{Enabled: true},
					}),
				},
			},
		})

		assert.False(t, oas.isProprietaryAuthScheme("jwtAuth"), "jwtAuth (JWT type) should be standard")
	})

	t.Run("should identify CustomPluginAuthentication in SecuritySchemes as proprietary", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"customPlugin": &CustomPluginAuthentication{Enabled: true},
					}),
				},
			},
		})

		assert.True(t, oas.isProprietaryAuthScheme("customPlugin"), "CustomPluginAuthentication should be proprietary")
	})

	t.Run("should identify standard types in SecuritySchemes as not proprietary", func(t *testing.T) {
		oas := &OAS{}
		trueVal := true
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwt":   &JWT{Enabled: true},
						"token": &Token{Enabled: &trueVal},
						"basic": &Basic{Enabled: true},
						"oauth": &ExternalOAuth{Enabled: true},
					}),
				},
			},
		})

		assert.False(t, oas.isProprietaryAuthScheme("jwt"), "JWT should be standard")
		assert.False(t, oas.isProprietaryAuthScheme("token"), "Token should be standard")
		assert.False(t, oas.isProprietaryAuthScheme("basic"), "Basic should be standard")
		assert.False(t, oas.isProprietaryAuthScheme("oauth"), "ExternalOAuth should be standard")
	})

	t.Run("should return false for unknown schemes not in vendor security or SecuritySchemes", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{},
			},
		})

		assert.False(t, oas.isProprietaryAuthScheme("unknownScheme"), "Unknown scheme should default to standard")
	})

	t.Run("should return false when no Tyk authentication is configured", func(t *testing.T) {
		oas := &OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{},
		})

		assert.False(t, oas.isProprietaryAuthScheme("anyScheme"), "Should return false when no authentication")
	})
}

func TestIsInVendorSecurity(t *testing.T) {
	t.Run("should find scheme in vendor security requirements", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{
			Security: [][]string{
				{"jwt", "apikey"},
				{"hmac"},
				{"customAuth"},
			},
		}

		assert.True(t, oas.isInVendorSecurity("jwt", auth), "jwt should be found")
		assert.True(t, oas.isInVendorSecurity("apikey", auth), "apikey should be found")
		assert.True(t, oas.isInVendorSecurity("hmac", auth), "hmac should be found")
		assert.True(t, oas.isInVendorSecurity("customAuth", auth), "customAuth should be found")
	})

	t.Run("should not find scheme not in vendor security", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{
			Security: [][]string{
				{"jwt"},
			},
		}

		assert.False(t, oas.isInVendorSecurity("basic", auth), "basic should not be found")
		assert.False(t, oas.isInVendorSecurity("oauth", auth), "oauth should not be found")
	})

	t.Run("should return false when vendor security is empty", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{
			Security: [][]string{},
		}

		assert.False(t, oas.isInVendorSecurity("jwt", auth), "Should return false for empty vendor security")
	})

	t.Run("should return false when vendor security is nil", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{}

		assert.False(t, oas.isInVendorSecurity("jwt", auth), "Should return false for nil vendor security")
	})
}

func TestIsProprietaryInVendor(t *testing.T) {
	t.Run("should return true when scheme not in OAS Components", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{}

		assert.True(t, oas.isProprietaryInVendor("customAuth", auth), "Should be proprietary when not in OAS Components")
	})

	t.Run("should return false when scheme in OAS Components and is standard type", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwtAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         typeHTTP,
						Scheme:       schemeBearer,
						BearerFormat: bearerFormatJWT,
					},
				},
			},
		}
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
				"jwtAuth": &JWT{Enabled: true},
			}),
		}

		assert.False(t, oas.isProprietaryInVendor("jwtAuth", auth), "JWT in both should be standard")
	})

	t.Run("should return true when scheme in OAS Components but is CustomPluginAuthentication", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"customAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{},
				},
			},
		}
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
				"customAuth": &CustomPluginAuthentication{Enabled: true},
			}),
		}

		assert.True(t, oas.isProprietaryInVendor("customAuth", auth), "CustomPluginAuthentication should be proprietary")
	})

	t.Run("should return false when scheme in OAS Components but not in SecuritySchemes", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"someAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{},
				},
			},
		}
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{}),
		}

		assert.False(t, oas.isProprietaryInVendor("someAuth", auth), "Should assume standard when can't determine type")
	})
}

func TestIsProprietaryInSecuritySchemes(t *testing.T) {
	t.Run("should return false when SecuritySchemes is nil", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{}

		assert.False(t, oas.isProprietaryInSecuritySchemes("anyScheme", auth), "Should return false for nil SecuritySchemes")
	})

	t.Run("should return false when scheme not in SecuritySchemes", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
				"jwt": &JWT{Enabled: true},
			}),
		}

		assert.False(t, oas.isProprietaryInSecuritySchemes("basic", auth), "Should return false when scheme doesn't exist")
	})

	t.Run("should return true for CustomPluginAuthentication", func(t *testing.T) {
		oas := &OAS{}
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
				"custom": &CustomPluginAuthentication{Enabled: true},
			}),
		}

		assert.True(t, oas.isProprietaryInSecuritySchemes("custom", auth), "CustomPluginAuthentication is proprietary")
	})

	t.Run("should return false for standard types", func(t *testing.T) {
		oas := &OAS{}
		trueVal := true
		auth := &Authentication{
			SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
				"jwt":   &JWT{Enabled: true},
				"token": &Token{Enabled: &trueVal},
				"basic": &Basic{Enabled: true},
				"oauth": &ExternalOAuth{Enabled: true},
			}),
		}

		assert.False(t, oas.isProprietaryInSecuritySchemes("jwt", auth), "JWT is standard")
		assert.False(t, oas.isProprietaryInSecuritySchemes("token", auth), "Token is standard")
		assert.False(t, oas.isProprietaryInSecuritySchemes("basic", auth), "Basic is standard")
		assert.False(t, oas.isProprietaryInSecuritySchemes("oauth", auth), "ExternalOAuth is standard")
	})
}

func TestIsInOASComponents(t *testing.T) {
	t.Run("should return true when scheme exists in Components", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwtAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{},
				},
				"apiKey": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{},
				},
			},
		}

		assert.True(t, oas.isInOASComponents("jwtAuth"), "jwtAuth should be found")
		assert.True(t, oas.isInOASComponents("apiKey"), "apiKey should be found")
	})

	t.Run("should return false when scheme not in Components", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"jwtAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{},
				},
			},
		}

		assert.False(t, oas.isInOASComponents("basic"), "basic should not be found")
		assert.False(t, oas.isInOASComponents("oauth"), "oauth should not be found")
	})

	t.Run("should return false when Components is nil", func(t *testing.T) {
		oas := &OAS{}

		assert.False(t, oas.isInOASComponents("anyScheme"), "Should return false when Components is nil")
	})

	t.Run("should return false when SecuritySchemes is nil", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{}

		assert.False(t, oas.isInOASComponents("anyScheme"), "Should return false when SecuritySchemes is nil")
	})

	t.Run("should return false when SecuritySchemes is empty", func(t *testing.T) {
		oas := &OAS{}
		oas.Components = &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{},
		}

		assert.False(t, oas.isInOASComponents("anyScheme"), "Should return false when SecuritySchemes is empty")
	})
}

func TestIsProprietarySchemeType(t *testing.T) {
	t.Run("should return false for JWT type", func(t *testing.T) {
		oas := &OAS{}
		scheme := &JWT{Enabled: true}

		assert.False(t, oas.isProprietarySchemeType(scheme), "JWT should be standard")
	})

	t.Run("should return false for Token type", func(t *testing.T) {
		oas := &OAS{}
		trueVal := true
		scheme := &Token{Enabled: &trueVal}

		assert.False(t, oas.isProprietarySchemeType(scheme), "Token should be standard")
	})

	t.Run("should return false for Basic type", func(t *testing.T) {
		oas := &OAS{}
		scheme := &Basic{Enabled: true}

		assert.False(t, oas.isProprietarySchemeType(scheme), "Basic should be standard")
	})

	t.Run("should return false for ExternalOAuth type", func(t *testing.T) {
		oas := &OAS{}
		scheme := &ExternalOAuth{Enabled: true}

		assert.False(t, oas.isProprietarySchemeType(scheme), "ExternalOAuth should be standard")
	})

	t.Run("should return true for CustomPluginAuthentication type", func(t *testing.T) {
		oas := &OAS{}
		scheme := &CustomPluginAuthentication{Enabled: true}

		assert.True(t, oas.isProprietarySchemeType(scheme), "CustomPluginAuthentication should be proprietary")
	})

	t.Run("should return true for unknown types", func(t *testing.T) {
		oas := &OAS{}
		scheme := struct{ Name string }{Name: "unknown"}

		assert.True(t, oas.isProprietarySchemeType(scheme), "Unknown types should be treated as proprietary")
	})

	t.Run("should return true for string type", func(t *testing.T) {
		oas := &OAS{}
		scheme := "someString"

		assert.True(t, oas.isProprietarySchemeType(scheme), "String type should be treated as proprietary")
	})

	t.Run("should return true for nil", func(t *testing.T) {
		oas := &OAS{}
		var scheme interface{} = nil

		assert.True(t, oas.isProprietarySchemeType(scheme), "nil should be treated as proprietary")
	})
}

func TestModeSwitching(t *testing.T) {
	t.Run("legacy to compliant with mixed auth", func(t *testing.T) {
		// Setup: Legacy mode with mixed auth (both standard and proprietary in OAS security)
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth"},
				{"customAuth"},
			},
			EnableJWT:               true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "customAuth",
					AuthHeaderName: "X-Custom-Auth",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant, // Switch to compliant
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"customAuth": &CustomPluginAuthentication{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill with compliant mode
		oas.fillSecurity(api)

		// Expected: jwtAuth in OAS security, customAuth in vendor security
		assert.Len(t, oas.T.Security, 1, "should have 1 OAS requirement")
		assert.Contains(t, oas.T.Security[0], "jwtAuth", "jwtAuth should be in OAS security")
		assert.NotContains(t, oas.T.Security[0], "customAuth", "customAuth should NOT be in OAS security")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should be populated")
		assert.Len(t, tykAuth.Security, 1, "should have 1 vendor requirement")
		assert.Contains(t, tykAuth.Security[0], "customAuth", "customAuth should be in vendor security")
	})

	t.Run("compliant to legacy preserves separation", func(t *testing.T) {
		// Setup: Compliant mode with properly separated auth
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth"},
				{"customAuth"},
			},
			EnableJWT:               true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "customAuth",
					AuthHeaderName: "X-Custom-Auth",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeLegacy, // Switch to legacy
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"customAuth": &CustomPluginAuthentication{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill with legacy mode
		oas.fillSecurity(api)

		// Expected: Separation maintained even in legacy mode
		assert.Len(t, oas.T.Security, 1, "should have 1 OAS requirement")
		assert.Contains(t, oas.T.Security[0], "jwtAuth", "jwtAuth should be in OAS security")
		assert.NotContains(t, oas.T.Security[0], "customAuth", "customAuth should NOT be in OAS security")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should be populated")
		assert.Len(t, tykAuth.Security, 1, "should have 1 vendor requirement")
		assert.Contains(t, tykAuth.Security[0], "customAuth", "customAuth should be in vendor security")
	})

	t.Run("add standard auth in compliant mode", func(t *testing.T) {
		// Setup: Compliant mode with existing auth
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth"},
				{"basicAuth"}, // Adding new standard auth
			},
			EnableJWT:    true,
			UseBasicAuth: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.BasicType: {
					Name:           "basicAuth",
					AuthHeaderName: "Authorization",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"basicAuth": &Basic{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: Both in OAS security
		assert.Len(t, oas.T.Security, 2, "should have 2 OAS requirements")

		var foundJwt, foundBasic bool
		for _, req := range oas.T.Security {
			if _, ok := req["jwtAuth"]; ok {
				foundJwt = true
			}
			if _, ok := req["basicAuth"]; ok {
				foundBasic = true
			}
		}
		assert.True(t, foundJwt, "jwtAuth should be in OAS security")
		assert.True(t, foundBasic, "basicAuth should be in OAS security")
	})

	t.Run("add proprietary auth in legacy mode", func(t *testing.T) {
		// Setup: Legacy mode with existing standard auth
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth"},
				{"hmac"}, // Adding proprietary auth
			},
			EnableJWT:               true,
			EnableSignatureChecking: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.HMACType: {
					Name:           "hmac",
					AuthHeaderName: "Authorization",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeLegacy,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"hmac": &HMAC{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: jwt in OAS, hmac in vendor
		assert.Len(t, oas.T.Security, 1, "should have 1 OAS requirement")
		assert.Contains(t, oas.T.Security[0], "jwtAuth", "jwtAuth should be in OAS security")
		assert.NotContains(t, oas.T.Security[0], "hmac", "hmac should NOT be in OAS security")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should be populated")
		assert.Len(t, tykAuth.Security, 1, "should have 1 vendor requirement")
		assert.Contains(t, tykAuth.Security[0], "hmac", "hmac should be in vendor security")
	})

	t.Run("round-trip preserves mode switching behavior", func(t *testing.T) {
		// Setup: Start with mixed auth
		originalAPI := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth"},
				{"customAuth"},
			},
			EnableJWT:               true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "customAuth",
					AuthHeaderName: "X-Custom-Auth",
				},
			},
		}

		// First fill with compliant mode
		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"customAuth": &CustomPluginAuthentication{
							Enabled: true,
						},
					}),
				},
			},
		})
		oas.fillSecurity(originalAPI)

		// Extract back to API
		var extractedAPI apidef.APIDefinition
		oas.extractSecurityTo(&extractedAPI)

		// Fill again with same mode
		oas2 := OAS{}
		oas2.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"customAuth": &CustomPluginAuthentication{
							Enabled: true,
						},
					}),
				},
			},
		})
		oas2.fillSecurity(extractedAPI)

		// Expected: Same separation maintained
		assert.Equal(t, oas.T.Security, oas2.T.Security, "OAS security should be preserved")

		tykAuth1 := oas.GetTykExtension().Server.Authentication
		tykAuth2 := oas2.GetTykExtension().Server.Authentication
		assert.Equal(t, tykAuth1.Security, tykAuth2.Security, "Vendor security should be preserved")
	})

	t.Run("mixed AND requirement in compliant mode", func(t *testing.T) {
		// Setup: Mixed requirement with both standard and proprietary (AND logic)
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"jwtAuth", "customAuth"}, // Mixed AND requirement
			},
			EnableJWT:               true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "customAuth",
					AuthHeaderName: "X-Custom-Auth",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"jwtAuth": &JWT{
							Enabled: true,
						},
						"customAuth": &CustomPluginAuthentication{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: Entire mixed requirement goes to vendor security
		assert.Len(t, oas.T.Security, 0, "OAS security should be empty for mixed requirements")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should be populated")
		assert.Len(t, tykAuth.Security, 1, "should have 1 vendor requirement")
		assert.Len(t, tykAuth.Security[0], 2, "vendor requirement should have 2 schemes")
		assert.Contains(t, tykAuth.Security[0], "jwtAuth", "jwtAuth should be in vendor security")
		assert.Contains(t, tykAuth.Security[0], "customAuth", "customAuth should be in vendor security")
	})

	t.Run("mixed requirement with hmac, custom, and jwt - bug fix verification", func(t *testing.T) {
		// Regression test for bug where jwtAuth was being moved from vendor security to OAS security
		// when part of a mixed requirement like [hmac, custom, jwtAuth]
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"hmac", "custom", "jwtAuth"}, // Three-way mixed AND requirement
			},
			EnableJWT:               true,
			EnableSignatureChecking: true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.HMACType: {
					Name:           "hmac",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "custom",
					AuthHeaderName: "X-Custom-Auth",
				},
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"hmac": &HMAC{
							Enabled: true,
						},
						"custom": &CustomPluginAuthentication{
							Enabled: true,
						},
						"jwtAuth": &JWT{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: ALL auth methods in vendor security, NONE in OAS security
		assert.Len(t, oas.T.Security, 0, "OAS security should be empty - jwtAuth should NOT be moved here")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.NotNil(t, tykAuth.Security, "vendor security should be populated")
		assert.Len(t, tykAuth.Security, 1, "should have exactly 1 vendor requirement")
		assert.Len(t, tykAuth.Security[0], 3, "vendor requirement should have all 3 schemes")
		assert.Contains(t, tykAuth.Security[0], "hmac", "hmac should be in vendor security")
		assert.Contains(t, tykAuth.Security[0], "custom", "custom should be in vendor security")
		assert.Contains(t, tykAuth.Security[0], "jwtAuth", "jwtAuth should stay in vendor security (not moved to OAS)")
	})

	t.Run("jwt not duplicated in both locations for mixed requirement", func(t *testing.T) {
		// Verify that JWT appears only in vendor security, not in both OAS and vendor
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"hmac", "jwtAuth"}, // Mixed requirement
			},
			EnableJWT:               true,
			EnableSignatureChecking: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.HMACType: {
					Name:           "hmac",
					AuthHeaderName: "Authorization",
				},
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"hmac": &HMAC{
							Enabled: true,
						},
						"jwtAuth": &JWT{
							Enabled: true,
						},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: JWT only in vendor security, not duplicated in OAS security
		assert.Empty(t, oas.T.Security, "OAS security must be empty - JWT should not be duplicated here")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.Len(t, tykAuth.Security, 1, "should have 1 vendor requirement")
		assert.Contains(t, tykAuth.Security[0], "jwtAuth", "jwtAuth should be in vendor security")
		assert.Contains(t, tykAuth.Security[0], "hmac", "hmac should be in vendor security")

		// Double-check JWT is not in OAS security
		for _, req := range oas.T.Security {
			assert.NotContains(t, req, "jwtAuth", "jwtAuth must NOT appear in OAS security when part of mixed requirement")
		}
	})

	t.Run("mixed requirement round-trip preserves location", func(t *testing.T) {
		// Test that mixed requirements survive round-trip without JWT being moved to OAS security
		originalAPI := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"hmac", "custom", "jwtAuth"},
			},
			EnableJWT:               true,
			EnableSignatureChecking: true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.HMACType: {
					Name:           "hmac",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "custom",
					AuthHeaderName: "X-Custom-Auth",
				},
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
			},
		}

		// First fill
		oas1 := OAS{}
		oas1.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"hmac":    &HMAC{Enabled: true},
						"custom":  &CustomPluginAuthentication{Enabled: true},
						"jwtAuth": &JWT{Enabled: true},
					}),
				},
			},
		})
		oas1.fillSecurity(originalAPI)

		// Extract
		var extractedAPI apidef.APIDefinition
		oas1.extractSecurityTo(&extractedAPI)

		// Second fill (round-trip)
		oas2 := OAS{}
		oas2.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"hmac":    &HMAC{Enabled: true},
						"custom":  &CustomPluginAuthentication{Enabled: true},
						"jwtAuth": &JWT{Enabled: true},
					}),
				},
			},
		})
		oas2.fillSecurity(extractedAPI)

		// Expected: Both iterations have same structure
		assert.Equal(t, oas1.T.Security, oas2.T.Security, "OAS security should be identical after round-trip")
		assert.Empty(t, oas2.T.Security, "OAS security should remain empty after round-trip")

		tykAuth1 := oas1.GetTykExtension().Server.Authentication
		tykAuth2 := oas2.GetTykExtension().Server.Authentication
		assert.Equal(t, tykAuth1.Security, tykAuth2.Security, "vendor security should be identical after round-trip")
		assert.Len(t, tykAuth2.Security, 1, "should still have 1 vendor requirement")
		assert.Contains(t, tykAuth2.Security[0], "jwtAuth", "jwtAuth should remain in vendor security")
	})

	t.Run("multiple mixed requirements stay in vendor security", func(t *testing.T) {
		// Test multiple mixed requirements (OR logic between them, AND within each)
		api := apidef.APIDefinition{
			SecurityRequirements: [][]string{
				{"hmac", "jwtAuth"},   // First mixed AND requirement
				{"custom", "jwtAuth"}, // Second mixed AND requirement
			},
			EnableJWT:               true,
			EnableSignatureChecking: true,
			CustomPluginAuthEnabled: true,
			AuthConfigs: map[string]apidef.AuthConfig{
				apidef.HMACType: {
					Name:           "hmac",
					AuthHeaderName: "Authorization",
				},
				apidef.CoprocessType: {
					Name:           "custom",
					AuthHeaderName: "X-Custom-Auth",
				},
				apidef.JWTType: {
					Name:           "jwtAuth",
					AuthHeaderName: "Authorization",
				},
			},
		}

		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					Enabled:                true,
					SecurityProcessingMode: SecurityProcessingModeCompliant,
					SecuritySchemes: newTestSecuritySchemes(map[string]interface{}{
						"hmac":    &HMAC{Enabled: true},
						"custom":  &CustomPluginAuthentication{Enabled: true},
						"jwtAuth": &JWT{Enabled: true},
					}),
				},
			},
		})

		// Action: Fill security
		oas.fillSecurity(api)

		// Expected: All requirements in vendor security, none in OAS
		assert.Empty(t, oas.T.Security, "OAS security should be empty for mixed requirements")

		tykAuth := oas.GetTykExtension().Server.Authentication
		assert.Len(t, tykAuth.Security, 2, "should have 2 vendor requirements")

		// First requirement: [hmac, jwtAuth]
		assert.Len(t, tykAuth.Security[0], 2, "first requirement should have 2 schemes")
		assert.Contains(t, tykAuth.Security[0], "hmac", "first requirement should contain hmac")
		assert.Contains(t, tykAuth.Security[0], "jwtAuth", "first requirement should contain jwtAuth")

		// Second requirement: [custom, jwtAuth]
		assert.Len(t, tykAuth.Security[1], 2, "second requirement should have 2 schemes")
		assert.Contains(t, tykAuth.Security[1], "custom", "second requirement should contain custom")
		assert.Contains(t, tykAuth.Security[1], "jwtAuth", "second requirement should contain jwtAuth")
	})
}
