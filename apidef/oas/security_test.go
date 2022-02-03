package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExtractSecuritySchemes(t *testing.T) {
	t.Run("basic auth", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"basic_auth": {
							Value: &openapi3.SecurityScheme{
								Type:   HTTP,
								Scheme: SchemeBasic,
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"basic_auth": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseBasicAuth)
	})

	t.Run("JWT", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"jwt_auth": {
							Value: &openapi3.SecurityScheme{
								Type:         HTTP,
								Scheme:       SchemeBearer,
								BearerFormat: BearerFormatJWT,
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"jwt_auth": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.EnableJWT)
	})

	t.Run("token auth - header", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"header": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InHeader,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"header": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			AuthHeaderName: "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("token auth - cookie", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"cookie": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InCookie,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"cookie": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			UseCookie:  true,
			CookieName: "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("token auth - query", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"query": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InQuery,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"query": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			UseParam:  true,
			ParamName: "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("token auth - header, cookie, query", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"header": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InHeader,
								Name: "Authorization",
							},
						},
						"cookie": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InCookie,
								Name: "Authorization",
							},
						},
						"query": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InQuery,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"header": []string{},
					},
					{
						"cookie": []string{},
					},
					{
						"query": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			AuthHeaderName: "Authorization",
			UseCookie:      false,
			CookieName:     "Authorization",
			UseParam:       false,
			ParamName:      "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("token auth - cookie, header, query", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"header": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InHeader,
								Name: "Authorization",
							},
						},
						"cookie": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InCookie,
								Name: "Authorization",
							},
						},
						"query": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InQuery,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"cookie": []string{},
					},
					{
						"header": []string{},
					},
					{
						"query": []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			AuthHeaderName: "Authorization",
			UseParam:       false,
			ParamName:      "Authorization",
			UseCookie:      true,
			CookieName:     "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("token auth (OR) cookie, header, query", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"header": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InHeader,
								Name: "Authorization",
							},
						},
						"cookie": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InCookie,
								Name: "Authorization",
							},
						},
						"query": {
							Value: &openapi3.SecurityScheme{
								Type: APIKey,
								In:   InQuery,
								Name: "Authorization",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"header": []string{},
						"cookie": []string{},
						"query":  []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseStandardAuth)
		assert.Equal(t, map[string]apidef.AuthConfig{"authToken": {
			AuthHeaderName: "Authorization",
			UseParam:       true,
			ParamName:      "Authorization",
			UseCookie:      true,
			CookieName:     "Authorization",
		}}, api.AuthConfigs)
	})

	t.Run("Oauth2 - authorization code", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									AuthorizationCode: &openapi3.OAuthFlow{
										AuthorizationURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"oauth2": []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.AUTHORIZATION_CODE,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
	})

	t.Run("Oauth2 - password", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									Password: &openapi3.OAuthFlow{
										TokenURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"oauth2": []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.PASSWORD,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
	})

	t.Run("Oauth2 - client credentials", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									ClientCredentials: &openapi3.OAuthFlow{
										TokenURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"oauth2": []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.CLIENT_CREDENTIALS,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
	})

	t.Run("OpenID connect", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"openIdConnect": {
							Value: &openapi3.SecurityScheme{
								Type:             OpenIDConnect,
								OpenIdConnectUrl: "https://example.com/api/openid/dialog",
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"openIdConnect": []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOpenID)
		assert.Equal(t, apidef.OpenIDOptions{
			Providers: []apidef.OIDProviderConfig{
				{
					Issuer: "https://example.com/api/openid/dialog",
				},
			},
		}, api.OpenIDOptions)
	})

	t.Run("OpenID connect OR oauth2", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"openIdConnect": {
							Value: &openapi3.SecurityScheme{
								Type:             OpenIDConnect,
								OpenIdConnectUrl: "https://example.com/api/openid/dialog",
							},
						},
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									ClientCredentials: &openapi3.OAuthFlow{
										TokenURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"openIdConnect": []string{"write:pets"},
					},
					{
						"oauth2": []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOpenID)
		assert.Equal(t, apidef.OpenIDOptions{
			Providers: []apidef.OIDProviderConfig{
				{
					Issuer: "https://example.com/api/openid/dialog",
				},
			},
		}, api.OpenIDOptions)
		assert.False(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.CLIENT_CREDENTIALS,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
		assert.Empty(t, api.BaseIdentityProvidedBy)
	})

	t.Run("OpenID connect AND oauth2", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"openIdConnect": {
							Value: &openapi3.SecurityScheme{
								Type:             OpenIDConnect,
								OpenIdConnectUrl: "https://example.com/api/openid/dialog",
							},
						},
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									ClientCredentials: &openapi3.OAuthFlow{
										TokenURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
						"jwt_auth": {
							Value: &openapi3.SecurityScheme{
								Type:         HTTP,
								Scheme:       SchemeBearer,
								BearerFormat: BearerFormatJWT,
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"openIdConnect": []string{"write:pets"},
						"oauth2":        []string{"write:pets"},
						"jwt_auth":      []string{},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOpenID)
		assert.Equal(t, apidef.OpenIDOptions{
			Providers: []apidef.OIDProviderConfig{
				{
					Issuer: "https://example.com/api/openid/dialog",
				},
			},
		}, api.OpenIDOptions)
		assert.True(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.CLIENT_CREDENTIALS,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
		// prone to fail since map doesn't preserve order
		assert.Equal(t, apidef.OIDCUser, api.BaseIdentityProvidedBy)
	})

	t.Run("OpenID connect AND oauth2 AND JWT", func(t *testing.T) {
		s := OAS{
			T: openapi3.T{
				Components: openapi3.Components{
					SecuritySchemes: map[string]*openapi3.SecuritySchemeRef{
						"openIdConnect": {
							Value: &openapi3.SecurityScheme{
								Type:             OpenIDConnect,
								OpenIdConnectUrl: "https://example.com/api/openid/dialog",
							},
						},
						"oauth2": {
							Value: &openapi3.SecurityScheme{
								Type: Oauth2,
								Flows: &openapi3.OAuthFlows{
									ClientCredentials: &openapi3.OAuthFlow{
										TokenURL: "https://example.com/api/oauth/dialog",
										Scopes: map[string]string{
											"write:pets": "modify pets in your account",
											"read:pets":  "read your pets",
										},
									},
								},
							},
						},
					},
				},
				Security: openapi3.SecurityRequirements{
					{
						"openIdConnect": []string{"write:pets"},
						"oauth2":        []string{"write:pets"},
					},
				},
			},
		}
		api := apidef.APIDefinition{}
		s.extractSecuritySchemes(&api, true)
		assert.True(t, api.UseOpenID)
		assert.Equal(t, apidef.OpenIDOptions{
			Providers: []apidef.OIDProviderConfig{
				{
					Issuer: "https://example.com/api/openid/dialog",
				},
			},
		}, api.OpenIDOptions)
		assert.True(t, api.UseOauth2)
		assert.Equal(t, struct {
			AllowedAccessTypes     []osin.AccessRequestType    `bson:"allowed_access_types" json:"allowed_access_types"`
			AllowedAuthorizeTypes  []osin.AuthorizeRequestType `bson:"allowed_authorize_types" json:"allowed_authorize_types"`
			AuthorizeLoginRedirect string                      `bson:"auth_login_redirect" json:"auth_login_redirect"`
		}{
			AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
				osin.CODE,
			},
			AllowedAccessTypes: []osin.AccessRequestType{
				osin.CLIENT_CREDENTIALS,
			},
			AuthorizeLoginRedirect: "https://example.com/api/oauth/dialog",
		}, api.Oauth2Meta)
		assert.False(t, api.EnableJWT)
		// prone to fail since map doesn't preserve order
		assert.Equal(t, apidef.OIDCUser, api.BaseIdentityProvidedBy)
	})
}

func TestFillSecuritySchemes(t *testing.T) {

}
