package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"
const Main = ""

type OAS struct {
	openapi3.T
}

func (s *OAS) Fill(api apidef.APIDefinition) {
	xTykAPIGateway := s.GetTykExtension()
	if xTykAPIGateway == nil {
		xTykAPIGateway = &XTykAPIGateway{}
		s.SetTykExtension(xTykAPIGateway)
	}

	xTykAPIGateway.Fill(api)
	s.fillPathsAndOperations(api.VersionData.Versions[Main].ExtendedPaths)
	s.fillSecurity(api)

	if ShouldOmit(xTykAPIGateway) {
		delete(s.Extensions, ExtensionTykAPIGateway)
	}

	if ShouldOmit(s.Extensions) {
		s.Extensions = nil
	}

	// set external docs to nil if populated with default values
	if ShouldOmit(s.ExternalDocs) {
		s.ExternalDocs = nil
	}
}

func (s *OAS) ExtractTo(api *apidef.APIDefinition) {
	if s.GetTykExtension() != nil {
		s.GetTykExtension().ExtractTo(api)
	}

	s.extractSecurityTo(api)

	versions := make(map[string]apidef.VersionInfo)
	versions[Main] = apidef.VersionInfo{}

	// Handle zero value (from json if empty) and nil paths (from code)
	if len(s.Paths) == 0 {
		var ep apidef.ExtendedPathsSet
		s.extractPathsAndOperations(&ep)

		versions[Main] = apidef.VersionInfo{
			UseExtendedPaths: true,
			ExtendedPaths:    ep,
		}
	}

	api.VersionData.Versions = versions
}

func (s *OAS) SetTykExtension(xTykAPIGateway *XTykAPIGateway) {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.Extensions[ExtensionTykAPIGateway] = xTykAPIGateway
}

func (s *OAS) GetTykExtension() *XTykAPIGateway {
	if s.Extensions == nil {
		return nil
	}

	if ext := s.Extensions[ExtensionTykAPIGateway]; ext != nil {
		rawTykAPIGateway, ok := ext.(json.RawMessage)
		if ok {
			var xTykAPIGateway XTykAPIGateway
			_ = json.Unmarshal(rawTykAPIGateway, &xTykAPIGateway)
			s.Extensions[ExtensionTykAPIGateway] = &xTykAPIGateway
			return &xTykAPIGateway
		}

		mapTykAPIGateway, ok := ext.(map[string]interface{})
		if ok {
			var xTykAPIGateway XTykAPIGateway
			dbByte, _ := json.Marshal(mapTykAPIGateway)
			_ = json.Unmarshal(dbByte, &xTykAPIGateway)
			s.Extensions[ExtensionTykAPIGateway] = &xTykAPIGateway
			return &xTykAPIGateway
		}

		return ext.(*XTykAPIGateway)
	}

	return nil
}

func (s *OAS) RemoveTykExtension() {

	if s.Extensions == nil {
		return
	}

	delete(s.Extensions, ExtensionTykAPIGateway)
}

func (s *OAS) getTykAuthentication() (authentication *Authentication) {
	if s.GetTykExtension() != nil {
		authentication = s.GetTykExtension().Server.Authentication
	}

	return
}

func (s *OAS) getTykTokenAuth(name string) (token *Token) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	token = &Token{}
	if tokenVal, ok := securityScheme.(*Token); ok {
		token = tokenVal
	} else {
		toStructIfMap(securityScheme, token)
	}

	s.getTykSecuritySchemes()[name] = token

	return
}

func (s *OAS) getTykJWTAuth(name string) (jwt *JWT) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	jwt = &JWT{}
	if jwtVal, ok := securityScheme.(*JWT); ok {
		jwt = jwtVal
	} else {
		toStructIfMap(securityScheme, jwt)
	}

	s.getTykSecuritySchemes()[name] = jwt

	return
}

func (s *OAS) getTykBasicAuth(name string) (basic *Basic) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	basic = &Basic{}
	if basicVal, ok := securityScheme.(*Basic); ok {
		basic = basicVal
	} else {
		toStructIfMap(securityScheme, basic)
	}

	s.getTykSecuritySchemes()[name] = basic

	return
}

func (s *OAS) getTykOAuthAuth(name string) (oauth *OAuth) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	oauth = &OAuth{}
	if oauthVal, ok := securityScheme.(*OAuth); ok {
		oauth = oauthVal
	} else {
		toStructIfMap(securityScheme, oauth)
	}

	s.getTykSecuritySchemes()[name] = oauth

	return
}

func (s *OAS) getTykSecuritySchemes() (securitySchemes SecuritySchemes) {
	if s.getTykAuthentication() != nil {
		securitySchemes = s.getTykAuthentication().SecuritySchemes
	}

	return
}

func (s *OAS) getTykSecurityScheme(name string) interface{} {
	securitySchemes := s.getTykSecuritySchemes()
	if securitySchemes == nil {
		return nil
	}

	return securitySchemes[name]
}

func (s *OAS) getTykMiddleware() (middleware *Middleware) {
	if s.GetTykExtension() != nil {
		middleware = s.GetTykExtension().Middleware
	}

	return
}

func (s *OAS) getTykOperations() (operations Operations) {
	if s.getTykMiddleware() != nil {
		operations = s.getTykMiddleware().Operations
	}

	return
}

func (s *OAS) AddServers(apiURL string) {
	if len(s.Servers) == 0 {
		s.Servers = openapi3.Servers{
			{
				URL: apiURL,
			},
		}
		return
	}

	newServers := openapi3.Servers{
		{
			URL: apiURL,
		},
	}

	// check if apiURL already exists in servers object
	for i := 0; i < len(s.Servers); i++ {
		if s.Servers[i].URL == apiURL {
			continue
		}
		newServers = append(newServers, s.Servers[i])
	}

	s.Servers = newServers
}

func (s *OAS) UpdateServers(apiURL, oldAPIURL string) {
	if len(s.Servers) == 0 {
		s.Servers = openapi3.Servers{
			{
				URL: apiURL,
			},
		}
		return
	}

	if len(s.Servers) > 0 && s.Servers[0].URL == oldAPIURL {
		s.Servers[0].URL = apiURL
	}
}
