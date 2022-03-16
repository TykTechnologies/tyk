package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

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
	s.fillSecurity(api)

	if ShouldOmit(xTykAPIGateway) {
		delete(s.Extensions, ExtensionTykAPIGateway)
	}

	if ShouldOmit(s.Extensions) {
		s.Extensions = nil
	}
}

func (s *OAS) ExtractTo(api *apidef.APIDefinition) {
	if s.Security != nil {
		s.extractSecurityTo(api)
	} else {
		api.UseKeylessAccess = true
	}

	if s.GetTykExtension() != nil {
		s.GetTykExtension().ExtractTo(api)
	}
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

func (s *OAS) getTykAuthentication() (authentication *Authentication) {
	if s.GetTykExtension() != nil {
		authentication = s.GetTykExtension().Server.Authentication
	}

	return
}

func (s *OAS) getTykTokenAuth(name string) (token *Token) {
	if securitySchemes := s.getTykSecuritySchemes(); securitySchemes != nil {
		securityScheme := securitySchemes[name]
		if securityScheme == nil {
			return
		}

		mapSecurityScheme, ok := securityScheme.(map[string]interface{})
		if ok {
			token = &Token{}
			inBytes, _ := json.Marshal(mapSecurityScheme)
			_ = json.Unmarshal(inBytes, token)
			s.getTykSecuritySchemes()[name] = token
			return
		}

		token = s.getTykSecuritySchemes()[name].(*Token)
	}

	return
}

func (s *OAS) getTykJWTAuth(name string) (jwt *JWT) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	mapSecurityScheme, ok := securityScheme.(map[string]interface{})
	if ok {
		jwt = &JWT{}
		inBytes, _ := json.Marshal(mapSecurityScheme)
		_ = json.Unmarshal(inBytes, jwt)
		s.getTykSecuritySchemes()[name] = jwt
		return
	}

	jwt = securityScheme.(*JWT)

	return
}

func (s *OAS) getTykBasicAuth(name string) (basic *Basic) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	mapSecurityScheme, ok := securityScheme.(map[string]interface{})
	if ok {
		basic = &Basic{}
		inBytes, _ := json.Marshal(mapSecurityScheme)
		_ = json.Unmarshal(inBytes, basic)
		s.getTykSecuritySchemes()[name] = basic
		return
	}

	basic = securityScheme.(*Basic)

	return
}

func (s *OAS) getTykOAuthAuth(name string) (oAuth *OAuth) {
	if securitySchemes := s.getTykSecuritySchemes(); securitySchemes != nil {
		securityScheme := securitySchemes[name]
		if securityScheme == nil {
			return
		}

		mapSecurityScheme, ok := securityScheme.(map[string]interface{})
		if ok {
			oAuth = &OAuth{}
			inBytes, _ := json.Marshal(mapSecurityScheme)
			_ = json.Unmarshal(inBytes, oAuth)
			s.getTykSecuritySchemes()[name] = oAuth
			return
		}

		oAuth = s.getTykSecuritySchemes()[name].(*OAuth)
	}

	return
}

func (s *OAS) getTykSecuritySchemes() (securitySchemes map[string]interface{}) {
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
