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
		s.fillApiKeyScheme(&ac)

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
		ac.AuthHeaderName = ""
		check(query, queryName, ac, OAS{})

		// reset
		ac.AuthHeaderName = headerName
	})

	t.Run("should not set cookie name in tyk extension", func(t *testing.T) {
		ac.AuthHeaderName = ""
		ac.ParamName = ""
		check(cookie, cookieName, ac, OAS{})

		// reset
		ac.AuthHeaderName = headerName
		ac.ParamName = queryName
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
		check(header, headerName, ac, testOAS(header, headerName))
	})

	t.Run("already filled scheme in=query value should be respected", func(t *testing.T) {
		check(query, queryName, ac, testOAS(query, queryName))
	})

	t.Run("already filled scheme in=cookie value should be respected", func(t *testing.T) {
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

	convertedOAS.SetTykExtension(&XTykAPIGateway{Server: Server{Authentication: &Authentication{SecuritySchemes: map[string]interface{}{}}}})
	convertedOAS.fillToken(api)

	assert.Equal(t, oas, convertedOAS)
}

func TestOAS_Token_EmptyTykAuthentication(t *testing.T) {
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

	var api apidef.APIDefinition
	oas.ExtractTo(&api)

	var convertedOAS OAS
	convertedOAS.Fill(api)

	assert.Equal(t, oas, convertedOAS)
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
