package oas

import (
	"sort"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

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
					Type: typeAPIKey,
					Name: "x-query",
					In:   query,
				},
			},
		},
	}

	var token Token
	Fill(t, &token, 0)
	token.Query = nil
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

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)
	oas.extractTokenTo(&api, securityName)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{
		SecuritySchemes: oas.Components.SecuritySchemes,
	}

	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: SecuritySchemes{}}}})
	convertedOAS.fillToken(api)

	assert.Equal(t, oas, convertedOAS)
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
						Enabled: true,
					},
				},
			},
		},
	}

	oas.SetTykExtension(xTykAPIGateway)

	var api apidef.APIDefinition
	err := oas.ExtractTo(&api)
	assert.NoError(t, err)

	var convertedOAS OAS
	err = convertedOAS.Fill(api)
	assert.NoError(t, err)

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
	err := oas.ExtractTo(&api)
	assert.NoError(t, err)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{SecuritySchemes: oas.Components.SecuritySchemes}
	err = convertedOAS.Fill(api)
	assert.NoError(t, err)
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
	err := oas.ExtractTo(&api)
	assert.NoError(t, err)

	var convertedOAS OAS
	convertedOAS.Components = &openapi3.Components{SecuritySchemes: oas.Components.SecuritySchemes}
	err = convertedOAS.Fill(api)
	assert.NoError(t, err)
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
