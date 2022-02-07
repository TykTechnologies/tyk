package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/lonelycode/osin"
)

func (s *OAS) extractSecuritySchemes(api *apidef.APIDefinition, enableSecurity bool) {
	// should not extract info when authEnabled is false
	if !enableSecurity || s.Security == nil {
		api.UseKeylessAccess = true
		return
	}
	var xTykAPIGateway = &XTykAPIGateway{}
	if s.Extensions == nil {
		s.Extensions = map[string]interface{}{
			ExtensionTykAPIGateway: xTykAPIGateway,
		}
	}
	if val, ok := s.Extensions[ExtensionTykAPIGateway]; !ok {
		s.Extensions[ExtensionTykAPIGateway] = xTykAPIGateway
	} else {
		xTykAPIGateway = val.(*XTykAPIGateway)
	}
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
					api.UseBasicAuth = i == 0
					if k == 0 {
						api.BaseIdentityProvidedBy = apidef.BasicAuthUser
					}
					if xTykAPIGateway.Server.Authentication.Basic != nil {
						xTykAPIGateway.Server.Authentication.Basic.ExtractTo(api)
					}
				} else if securityScheme.Scheme == SchemeBearer && securityScheme.BearerFormat == BearerFormatJWT {
					api.EnableJWT = i == 0
					if k == 0 {
						api.BaseIdentityProvidedBy = apidef.JWTClaim
					}
					if xTykAPIGateway.Server.Authentication.JWT != nil {
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
						api.Oauth2Meta.AllowedAuthorizeTypes = []osin.AuthorizeRequestType{
							osin.CODE,
						}
					} else {
						api.Oauth2Meta.AllowedAuthorizeTypes = append(api.Oauth2Meta.AllowedAuthorizeTypes, osin.CODE)
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
						api.Oauth2Meta.AuthorizeLoginRedirect = securityScheme.Flows.Password.TokenURL
						if i > 0 {
							oAuth.AllowedAccessTypes = append(oAuth.AllowedAccessTypes, osin.PASSWORD)
							oAuth.AuthLoginRedirect = securityScheme.Flows.Password.TokenURL
						}
					}
					if securityScheme.Flows.ClientCredentials != nil {
						api.Oauth2Meta.AllowedAccessTypes = append(api.Oauth2Meta.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
						api.Oauth2Meta.AuthorizeLoginRedirect = securityScheme.Flows.ClientCredentials.TokenURL
						if i > 0 {
							oAuth.AllowedAccessTypes = append(oAuth.AllowedAccessTypes, osin.CLIENT_CREDENTIALS)
							oAuth.AuthLoginRedirect = securityScheme.Flows.ClientCredentials.TokenURL
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
	var xTykAPIGateway = &XTykAPIGateway{}
	if s.Extensions == nil {
		s.Extensions = map[string]interface{}{
			ExtensionTykAPIGateway: xTykAPIGateway,
		}
	}
	xTykAPIGateway = s.Extensions[ExtensionTykAPIGateway].(*XTykAPIGateway)
	if xTykAPIGateway.Server.Authentication == nil {
		xTykAPIGateway.Server.Authentication = &Authentication{}
	}
	securitySchemes := s.Components.SecuritySchemes
	if securitySchemes == nil {
		securitySchemes = openapi3.SecuritySchemes{}
	}
	security := s.Security
	if security == nil {
		security = openapi3.SecurityRequirements{}
	}
	// APIKey
	if authToken, ok := api.AuthConfigs["authToken"]; ok {
		// use header auth as the first one
		if authToken.AuthHeaderName != "" && xTykAPIGateway.Server.Authentication.Token.Enabled {
			securityScheme := openapi3.SecurityScheme{
				In:   InHeader,
				Type: APIKey,
				Name: authToken.AuthHeaderName,
			}
			securitySchemes[HeaderKey] = &openapi3.SecuritySchemeRef{
				Value: &securityScheme,
			}
			security = append(security, openapi3.SecurityRequirement{
				HeaderKey: []string{},
			})
		}
		if authToken.UseCookie && xTykAPIGateway.Server.Authentication.Token.Cookie.Enabled {
			securityScheme := openapi3.SecurityScheme{
				In:   InCookie,
				Type: APIKey,
				Name: authToken.CookieName,
			}
			securitySchemes[CookieKey] = &openapi3.SecuritySchemeRef{
				Value: &securityScheme,
			}
			security = append(security, openapi3.SecurityRequirement{
				CookieKey: []string{},
			})
		}
		if authToken.UseParam && xTykAPIGateway.Server.Authentication.Token.Param.Enabled {
			securityScheme := openapi3.SecurityScheme{
				In:   InQuery,
				Type: APIKey,
				Name: authToken.ParamName,
			}
			securitySchemes[QueryKey] = &openapi3.SecuritySchemeRef{
				Value: &securityScheme,
			}
			security = append(security, openapi3.SecurityRequirement{
				QueryKey: []string{},
			})
		}
	}
	// HTTP basic auth
	if api.UseBasicAuth {
		securityScheme := openapi3.SecurityScheme{
			Type:   HTTP,
			Scheme: SchemeBasic,
		}
		securitySchemes[BasicKey] = &openapi3.SecuritySchemeRef{
			Value: &securityScheme,
		}
		security = append(security, openapi3.SecurityRequirement{})
	}
	if api.EnableJWT {
		securityScheme := openapi3.SecurityScheme{
			Type:   HTTP,
			Scheme: SchemeBearer,
		}
		securitySchemes[JWTKey] = &openapi3.SecuritySchemeRef{
			Value: &securityScheme,
		}
		security = append(security, openapi3.SecurityRequirement{})
	}
	if api.UseOpenID {
		securityScheme := openapi3.SecurityScheme{
			Type:             OpenIDConnect,
			OpenIdConnectUrl: api.OpenIDOptions.Providers[0].Issuer,
		}
		securitySchemes[OpenIDConnect] = &openapi3.SecuritySchemeRef{
			Value: &securityScheme,
		}
		security = append(security, openapi3.SecurityRequirement{})
	}
	if api.UseOauth2 {
		securityScheme := openapi3.SecurityScheme{
			Type:  Oauth2,
			Flows: &openapi3.OAuthFlows{},
		}
		for _, allowedRequestType := range api.Oauth2Meta.AllowedAccessTypes {
			switch allowedRequestType {
			case osin.AUTHORIZATION_CODE:
				securityScheme.Flows.AuthorizationCode = &openapi3.OAuthFlow{
					AuthorizationURL: api.Oauth2Meta.AuthorizeLoginRedirect,
				}
			case osin.PASSWORD:
				securityScheme.Flows.Password = &openapi3.OAuthFlow{
					AuthorizationURL: api.Oauth2Meta.AuthorizeLoginRedirect,
				}
			case osin.CLIENT_CREDENTIALS:
				securityScheme.Flows.AuthorizationCode = &openapi3.OAuthFlow{
					AuthorizationURL: api.Oauth2Meta.AuthorizeLoginRedirect,
				}
			}
		}
		securitySchemes[Oauth2] = &openapi3.SecuritySchemeRef{
			Value: &securityScheme,
		}
		security = append(security, openapi3.SecurityRequirement{})
	}
	s.Components.SecuritySchemes = securitySchemes
	s.Security = security
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
	} else {
		api.AuthConfigs = map[string]apidef.AuthConfig{}
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
