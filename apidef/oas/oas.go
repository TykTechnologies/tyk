package oas

import (
	"encoding/json"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

// ExtensionTykAPIGateway is the OAS schema key for the Tyk extension.
const ExtensionTykAPIGateway = "x-tyk-api-gateway"

// Main holds the default version value (empty).
const Main = ""

// OAS holds the upstream OAS definition as well as adds functionality like custom JSON marshalling.
type OAS struct {
	openapi3.T
}

// MarshalJSON implements json.Marshaller.
func (s *OAS) MarshalJSON() ([]byte, error) {
	if ShouldOmit(s.ExternalDocs) { // for sql case
		s.ExternalDocs = nil
	}

	if s.Info != nil && ShouldOmit(s.Info.License) { // for sql case
		s.Info.License = nil
	}

	// when OAS object is unmarshalled, the extension values are marshalled as plain []byte by kin/openapi
	// this causes json marshaller to base64 encode the values - https://pkg.go.dev/encoding/json#Marshal.
	// this block converts the extensions to json.RawMessage so that it's correctly marshalled.
	for k := range s.Extensions {
		if k == ExtensionTykAPIGateway {
			continue
		}

		if byteV, ok := s.Extensions[k].([]byte); ok {
			s.Extensions[k] = json.RawMessage(byteV)
		}
	}

	type Alias OAS

	// to prevent infinite recursion
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// Fill fills *OAS definition from apidef.APIDefinition.
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

// ExtractTo extracts *OAS into *apidef.APIDefinition.
func (s *OAS) ExtractTo(api *apidef.APIDefinition) {
	if s.GetTykExtension() != nil {
		s.GetTykExtension().ExtractTo(api)
	}

	s.extractSecurityTo(api)

	var ep apidef.ExtendedPathsSet
	s.extractPathsAndOperations(&ep)

	api.VersionData.Versions = map[string]apidef.VersionInfo{
		Main: {
			UseExtendedPaths: true,
			ExtendedPaths:    ep,
		},
	}
}

// SetTykExtension populates our OAS schema extension inside *OAS.
func (s *OAS) SetTykExtension(xTykAPIGateway *XTykAPIGateway) {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.Extensions[ExtensionTykAPIGateway] = xTykAPIGateway
}

// GetTykExtension returns our OAS schema extension from inside *OAS.
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

// RemoveTykExtension clears the Tyk extensions from *OAS.
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

func (s *OAS) getTykExternalOAuthAuth(name string) (externalOAuth *ExternalOAuth) {
	securityScheme := s.getTykSecurityScheme(name)
	if securityScheme == nil {
		return
	}

	externalOAuth = &ExternalOAuth{}
	if oauthVal, ok := securityScheme.(*ExternalOAuth); ok {
		externalOAuth = oauthVal
	} else {
		toStructIfMap(securityScheme, externalOAuth)
	}

	s.getTykSecuritySchemes()[name] = externalOAuth

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

// AddServers adds a server into the servers definition if not already present.
func (s *OAS) AddServers(apiURLs ...string) {
	apiURLSet := make(map[string]struct{})
	newServers := openapi3.Servers{}
	for _, apiURL := range apiURLs {
		newServers = append(newServers, &openapi3.Server{
			URL: apiURL,
		})
		apiURLSet[apiURL] = struct{}{}
	}

	if len(s.Servers) == 0 {
		s.Servers = newServers
		return
	}

	// check if apiURL already exists in servers object
	for i := 0; i < len(s.Servers); i++ {
		if _, ok := apiURLSet[s.Servers[i].URL]; ok {
			continue
		}

		newServers = append(newServers, s.Servers[i])
	}

	s.Servers = newServers
}

// UpdateServers sets or updates the first servers URL if it matches oldAPIURL.
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

// ReplaceServers replaces OAS servers entry having oldAPIURLs with new apiURLs .
func (s *OAS) ReplaceServers(apiURLs, oldAPIURLs []string) {
	if len(s.Servers) == 0 && len(apiURLs) == 1 {
		s.Servers = openapi3.Servers{
			{
				URL: apiURLs[0],
			},
		}
		return
	}

	oldAPIURLSet := make(map[string]struct{})
	for _, apiURL := range oldAPIURLs {
		oldAPIURLSet[apiURL] = struct{}{}
	}

	newServers := openapi3.Servers{}
	for _, apiURL := range apiURLs {
		newServers = append(newServers, &openapi3.Server{URL: apiURL})
	}

	userAddedServers := openapi3.Servers{}
	for _, server := range s.Servers {
		if _, ok := oldAPIURLSet[server.URL]; ok {
			continue
		}
		userAddedServers = append(userAddedServers, server)
	}

	s.Servers = append(newServers, userAddedServers...)
}
