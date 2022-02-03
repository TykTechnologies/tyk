package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
)

func (s *OAS) extractSecuritySchemes(api *apidef.APIDefinition, enableSecurity bool) {
	// should not extract info when authEnabled is false
	if !enableSecurity {
		return
	}
	xTykAPIGateway := s.Extensions[ExtensionTykAPIGateway].(*XTykAPIGateway)
	if xTykAPIGateway.Server.Authentication == nil {
		xTykAPIGateway.Server.Authentication = &Authentication{}
	}
	// when there are multiple security requirements use the first one in the array
	for i, security := range s.Security {
		k := 0
		for securitySchemeName := range security {
			securityScheme := s.getSecuritySchemeByName(securitySchemeName)
			switch securityScheme.Type {
			case APIKey:
				if k == 0 {
					api.BaseIdentityProvidedBy = apidef.AuthToken
				}
				if xTykAPIGateway.Server.Authentication.Token == nil {
					xTykAPIGateway.Server.Authentication.Token = &Token{
						Enabled: i == 0,
					}
				}
				if i == 0 {
					extractTokenAuth(true, securityScheme, api)
				} else {
					extractTokenAuth(false, securityScheme, api)
					// update x-tyk-gateway when there are more than one auth specified
					tokenAuthConfig := xTykAPIGateway.Server.Authentication.Token
					switch securityScheme.In {
					case InHeader:
						tokenAuthConfig.Header = HeaderAuthSource{
							Name: securityScheme.Name,
						}
					case InCookie:
						tokenAuthConfig.Cookie = &AuthSource{
							Name:    securityScheme.Name,
							Enabled: true,
						}
					case InQuery:
						tokenAuthConfig.Cookie = &AuthSource{
							Name:    securityScheme.Name,
							Enabled: true,
						}
					}
				}
			case HTTP:
				if securityScheme.Scheme == SchemeBasic {
					if k == 0 {
						api.BaseIdentityProvidedBy = apidef.BasicAuthUser
					}
					if xTykAPIGateway.Server.Authentication.Basic == nil {
						xTykAPIGateway.Server.Authentication.Basic = &Basic{
							Enabled: i == 0,
						}
					} else {
						xTykAPIGateway.Server.Authentication.Basic.ExtractTo(api)
					}
				} else if securityScheme.Scheme == SchemeBearer && securityScheme.BearerFormat == BearerFormatJWT {
					if k == 0 {
						api.BaseIdentityProvidedBy = apidef.JWTClaim
					}
					if xTykAPIGateway.Server.Authentication.JWT == nil {
						xTykAPIGateway.Server.Authentication.JWT = &JWT{
							Enabled: i == 0,
						}
					} else {
						xTykAPIGateway.Server.Authentication.JWT.ExtractTo(api)
					}
				}
			case OpenIDConnect:
				api.UseOpenID = i == 0
				if k == 0 {
					api.BaseIdentityProvidedBy = apidef.OIDCUser
				}
				if xTykAPIGateway.Server.Authentication.OIDC == nil {
					xTykAPIGateway.Server.Authentication.OIDC = &OIDC{
						Enabled: i == 0,
					}
					if i == 0 {
						api.OpenIDOptions = apidef.OpenIDOptions{
							Providers: []apidef.OIDProviderConfig{
								{
									Issuer: securityScheme.OpenIdConnectUrl,
								},
							},
						}
					} else {
						xTykAPIGateway.Server.Authentication.OIDC.Providers = []Provider{
							{
								Issuer: securityScheme.OpenIdConnectUrl,
							},
						}
					}

				} else {
					xTykAPIGateway.Server.Authentication.OIDC.ExtractTo(api)
				}
			case Oauth2:
				api.UseOauth2 = i == 0
				if k == 0 {
					api.BaseIdentityProvidedBy = apidef.OAuthKey
				}
				if xTykAPIGateway.Server.Authentication.OAuth == nil {
					oAuth := &OAuth{
						Enabled: i == 0,
						AuthSources: AuthSources{
							Header: HeaderAuthSource{
								Name: Authorization,
							},
						},
						AllowedAccessTypes: []osin.AccessRequestType{},
						AllowedAuthorizeTypes: []osin.AuthorizeRequestType{
							osin.CODE,
						},
					}
					if api.Oauth2Meta.AllowedAuthorizeTypes == nil {
						api.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{}
					}
					if api.Oauth2Meta.AllowedAccessTypes == nil {
						api.Oauth2Meta.AllowedAccessTypes = []osin.AccessRequestType{}
					}
					if securityScheme.Flows.AuthorizationCode != nil {
						api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.AUTHORIZATION_CODE)
						api.Oauth2Meta.AuthorizeLoginRedirect = securityScheme.Flows.AuthorizationCode.AuthorizationURL
						if i > 0 {
							oAuth.AllowedAccessTypes = append(oAuth.AllowedAccessTypes, osin.AUTHORIZATION_CODE)
							oAuth.AuthLoginRedirect = securityScheme.Flows.AuthorizationCode.AuthorizationURL
						}
					}
					if securityScheme.Flows.Password != nil {
						api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.PASSWORD)
						api.Oauth2Meta.AuthorizeLoginRedirect = securityScheme.Flows.Password.AuthorizationURL
						if i > 0 {
							oAuth.AllowedAccessTypes = append(oAuth.AllowedAccessTypes, osin.PASSWORD)
							oAuth.AuthLoginRedirect = securityScheme.Flows.Password.AuthorizationURL
						}
					}
					if securityScheme.Flows.ClientCredentials != nil {
						api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
						api.Oauth2Meta.AuthorizeLoginRedirect = securityScheme.Flows.ClientCredentials.AuthorizationURL
						if i > 0 {
							oAuth.AllowedAccessTypes = append(oAuth.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
							oAuth.AuthLoginRedirect = securityScheme.Flows.ClientCredentials.AuthorizationURL
						}
					}
					xTykAPIGateway.Server.Authentication.OAuth = oAuth
				} else {
					xTykAPIGateway.Server.Authentication.OAuth.ExtractTo(api)
				}
			}
			k++
		}
		// disable multi auth
		if k == 1 {
			api.BaseIdentityProvidedBy = ""
		}
	}
}

func (s *OAS) getSecuritySchemeByName(schemeName string) *openapi3.SecurityScheme {
	securityScheme := s.Components.SecuritySchemes[schemeName].Value
	if securityScheme != nil {
		return securityScheme
	}
	return nil
}

func (s *OAS) fillSecuritySchemes(api *apidef.APIDefinition) {
	xTykAPIGateway := s.Extensions[ExtensionTykAPIGateway].(*XTykAPIGateway)
	if xTykAPIGateway.Server.Authentication == nil {
		xTykAPIGateway.Server.Authentication = &Authentication{}
	}
	// APIKey
	if authToken, ok := api.AuthConfigs["authToken"]; ok {
		token := &Token{}
		token.Fill(true, authToken)
		xTykAPIGateway.Server.Authentication.Token = token
	}
	// HTTP basic auth
	if api.UseBasicAuth {
		basic := &Basic{}
		basic.Fill(*api)
		xTykAPIGateway.Server.Authentication.Basic = basic
	}

}

func extractTokenAuth(enable bool, apiKeySecurityScheme *openapi3.SecurityScheme, api *apidef.APIDefinition) {
	api.UseStandardAuth = true
	var authTokenConfig apidef.AuthConfig
	if api.AuthConfigs != nil {
		ok := false
		authTokenConfig, ok = api.AuthConfigs["authToken"]
		if !ok {
			api.AuthConfigs["authToken"] = authTokenConfig
		}
	}
	switch apiKeySecurityScheme.In {
	case InHeader:
		authTokenConfig.AuthHeaderName = apiKeySecurityScheme.Name
	case InCookie:
		authTokenConfig.UseCookie = enable
		authTokenConfig.CookieName = apiKeySecurityScheme.Name
	case InQuery:
		authTokenConfig.UseParam = enable
		authTokenConfig.ParamName = apiKeySecurityScheme.Name
	}
	api.AuthConfigs["authToken"] = authTokenConfig
}
