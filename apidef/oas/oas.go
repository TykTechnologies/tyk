package oas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/config"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	// ExtensionTykAPIGateway is the OAS schema key for the Tyk extension.
	ExtensionTykAPIGateway = "x-tyk-api-gateway"

	// ExtensionTykStreaming is the OAS schema key for the Tyk Streams extension.
	ExtensionTykStreaming = "x-tyk-streaming"

	// Main holds the default version value (empty).
	Main = ""

	// DefaultOpenAPI is the default open API version which is set to migrated APIs.
	DefaultOpenAPI = "3.0.6"
)

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
	if s.GetTykExtension() == nil {
		s.SetTykExtension(&XTykAPIGateway{})
		defer func() {
			delete(s.Extensions, ExtensionTykAPIGateway)
		}()
	}

	s.GetTykExtension().ExtractTo(api)

	s.extractSecurityTo(api)

	vInfo := api.VersionData.Versions[Main]
	vInfo.UseExtendedPaths = true
	s.extractPathsAndOperations(&vInfo.ExtendedPaths)
	api.VersionData.Versions[Main] = vInfo
}

func (s *OAS) SetTykStreamingExtension(xTykStreaming *XTykStreaming) {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.Extensions[ExtensionTykStreaming] = xTykStreaming
}

func (s *OAS) GetTykStreamingExtension() *XTykStreaming {
	if s.Extensions == nil {
		return nil
	}

	if ext := s.Extensions[ExtensionTykStreaming]; ext != nil {
		rawTykStreaming, ok := ext.(json.RawMessage)
		if ok {
			var xTykStreaming XTykStreaming
			_ = json.Unmarshal(rawTykStreaming, &xTykStreaming)
			s.Extensions[ExtensionTykStreaming] = &xTykStreaming
			return &xTykStreaming
		}

		mapTykAPIGateway, ok := ext.(map[string]interface{})
		if ok {
			var xTykStreaming XTykStreaming
			dbByte, _ := json.Marshal(mapTykAPIGateway)
			_ = json.Unmarshal(dbByte, &xTykStreaming)
			s.Extensions[ExtensionTykStreaming] = &xTykStreaming
			return &xTykStreaming
		}

		return ext.(*XTykStreaming)
	}

	return nil
}

func (s *OAS) RemoveTykStreamingExtension() {
	if s.Extensions == nil {
		return
	}

	delete(s.Extensions, ExtensionTykStreaming)
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

// Clone creates a deep copy of the OAS object and returns a new instance.
func (s *OAS) Clone() (*OAS, error) {
	oasInBytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	var retOAS OAS
	_ = json.Unmarshal(oasInBytes, &retOAS)

	// convert Tyk extension from map to struct
	retOAS.GetTykExtension()

	return &retOAS, nil
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

// GetTykMiddleware returns middleware section from XTykAPIGateway.
func (s *OAS) GetTykMiddleware() (middleware *Middleware) {
	if s.GetTykExtension() != nil {
		middleware = s.GetTykExtension().Middleware
	}

	return
}

func (s *OAS) getTykOperations() (operations Operations) {
	if s.GetTykMiddleware() != nil {
		operations = s.GetTykMiddleware().Operations
	}

	return
}

// AddServers adds a server into the servers definition if not already present.
func (s *OAS) AddServers(apiURLs ...string) {
	apiURLSet := make(map[string]struct{})
	newServers := openapi3.Servers{}
	for _, apiURL := range apiURLs {
		if strings.Contains(apiURL, "{") && strings.Contains(apiURL, "}") {
			continue
		}

		newServers = append(newServers, &openapi3.Server{
			URL: apiURL,
		})
		apiURLSet[apiURL] = struct{}{}
	}

	if len(newServers) == 0 {
		return
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
	apiURLContainsNamedRegex := strings.Contains(apiURL, "{") && strings.Contains(apiURL, "}")
	serverAddedByTyk := len(s.Servers) > 0 && s.Servers[0].URL == oldAPIURL

	if apiURLContainsNamedRegex && serverAddedByTyk {
		s.Servers = s.Servers[1:]
		return
	}

	if serverAddedByTyk {
		s.Servers[0].URL = apiURL
	}

	if len(s.Servers) == 0 {
		s.Servers = openapi3.Servers{
			{
				URL: apiURL,
			},
		}
		return
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

// APIDef holds both OAS and Classic forms of an API definition.
type APIDef struct {
	// OAS contains the OAS API definition.
	OAS *OAS
	// Classic contains the Classic API definition.
	Classic *apidef.APIDefinition
}

// MigrateAndFillOAS migrates classic APIs to OAS-compatible forms. Then, it fills an OAS with it. To be able to make it
// a valid OAS, it adds some required fields. It returns base API and its versions if any.
func MigrateAndFillOAS(api *apidef.APIDefinition) (APIDef, []APIDef, error) {
	baseAPIDef := APIDef{Classic: api}

	versions, err := api.Migrate()
	if err != nil {
		return baseAPIDef, nil, err
	}

	baseAPIDef.OAS, err = newOASFromClassicAPIDefinition(api)
	if err != nil {
		return baseAPIDef, nil, fmt.Errorf("base API %s migrated OAS is not valid: %w", api.Name, err)
	}

	versionAPIDefs := make([]APIDef, len(versions))
	for i := 0; i < len(versions); i++ {
		versionOAS, err := newOASFromClassicAPIDefinition(&versions[i])
		if err != nil {
			return baseAPIDef, nil, fmt.Errorf("version API %s migrated OAS is not valid: %w", versions[i].Name, err)
		}
		versionAPIDefs[i] = APIDef{versionOAS, &versions[i]}
	}

	return baseAPIDef, versionAPIDefs, err
}

func newOASFromClassicAPIDefinition(api *apidef.APIDefinition) (*OAS, error) {
	api.IsOAS = true
	var oas OAS
	oas.Fill(*api)
	oas.setRequiredFields(api.Name, api.VersionName)
	clearClassicAPIForSomeFeatures(api)

	err := oas.Validate(context.Background(), []openapi3.ValidationOption{
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation(),
	}...)
	if err != nil {
		return nil, err
	}

	bytes, err := oas.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return &oas, ValidateOASObject(bytes, oas.OpenAPI)
}

// setRequiredFields sets some required fields to make OAS object a valid one.
func (s *OAS) setRequiredFields(name string, versionName string) {
	s.OpenAPI = DefaultOpenAPI
	s.Info = &openapi3.Info{
		Title:   name,
		Version: versionName,
	}
}

// clearClassicAPIForSomeFeatures clears some features that will be OAS-only.
// For example, the new validate request will just be valid for OAS APIs so after migrating from classic API definition
// the existing feature should be cleared to prevent ValidateJSON middleware interference.
func clearClassicAPIForSomeFeatures(api *apidef.APIDefinition) {
	// clear ValidateJSON after migration to OAS-only ValidateRequest
	vInfo := api.VersionData.Versions[Main]
	vInfo.ExtendedPaths.ValidateJSON = nil
	api.VersionData.Versions[Main] = vInfo
}

// GetValidationOptionsFromConfig retrieves validation options based on the configuration settings.
func GetValidationOptionsFromConfig(oasConfig config.OASConfig) []openapi3.ValidationOption {
	var opts []openapi3.ValidationOption

	if !oasConfig.ValidateSchemaDefaults {
		opts = append(opts, openapi3.DisableSchemaDefaultsValidation())
	}

	if !oasConfig.ValidateExamples {
		opts = append(opts, openapi3.DisableExamplesValidation())
	}

	return opts
}
