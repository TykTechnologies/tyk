package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestOAS_Security(t *testing.T) {
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

	var convertedAPI apidef.APIDefinition
	oas.extractSecurityTo(&convertedAPI)

	assert.Equal(t, api, convertedAPI)
}

func TestOAS_SecurityScheme(t *testing.T) {
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
		s.fillSecurityScheme(&ac)

		expectedAC := ac
		expExtractedAC := apidef.AuthConfig{Name: authName}

		switch in {
		case header:
			expectedAC.AuthHeaderName = ""
			expExtractedAC.AuthHeaderName = name
		case query:
			expectedAC.ParamName = ""
			expExtractedAC.ParamName = name
		case cookie:
			expectedAC.CookieName = ""
			expExtractedAC.CookieName = name
		}

		expSecurity := openapi3.SecurityRequirements{
			{
				authName: []string{},
			},
		}

		expSecuritySchemes := openapi3.SecuritySchemes{
			authName: &openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{
					Type: apiKey,
					In:   in,
					Name: name,
				},
			},
		}

		assert.Equal(t, expSecurity, s.Security)
		assert.Equal(t, expSecuritySchemes, s.Components.SecuritySchemes)
		assert.Equal(t, expectedAC, ac)

		var extractedAC apidef.AuthConfig
		s.extractApiKeySchemeTo(&extractedAC, authName)

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
		oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
			authName: &openapi3.SecuritySchemeRef{
				Value: &openapi3.SecurityScheme{
					Type: apiKey,
					In:   in,
					Name: name,
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

	oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
		securityName: {
			Value: &openapi3.SecurityScheme{
				Type: apiKey,
				Name: "x-query",
				In:   query,
			},
		},
	}

	var token Token
	Fill(t, &token, 0)
	token.Query.Name = ""
	oas.Extensions = map[string]interface{}{
		ExtensionTykAPIGateway: &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: map[string]interface{}{
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
	convertedOAS.Components.SecuritySchemes = oas.Components.SecuritySchemes

	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{}}})
	convertedOAS.fillToken(api)

	assert.Equal(t, oas, convertedOAS)
}
