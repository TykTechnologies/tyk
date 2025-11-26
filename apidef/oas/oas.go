package oas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/samber/lo"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/TykTechnologies/tyk/internal/reflect"

	"github.com/getkin/kin-openapi/openapi3"
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
	return reflect.Clone(s), nil
}

func (s *OAS) getTykAuthentication() (authentication *Authentication) {
	if s.GetTykExtension() != nil {
		authentication = s.GetTykExtension().Server.Authentication
	}

	return
}

// getTypedSchema atomically promotes a scheme from map[string]interface{} to *T,
// caching the result. It uses a fast path under RLock and a slow path under Lock.
func getTypedSchema[T SecuritySchemeMarker](s *OAS, key string) T {
	res, _ := s.getTykSecuritySchemes().Get(key)

	if val, ok := res.(T); ok {
		return val
	}

	var zero T
	return zero
}

func (s *OAS) getTykTokenAuth(name string) *Token {
	return getTypedSchema[*Token](s, name)
}

func (s *OAS) getTykJWTAuth(name string) *JWT {
	return getTypedSchema[*JWT](s, name)
}

// getTykBasicAuth returns the `Basic` security scheme for the given name from the
// Tyk extension, normalizing map-based representations into `*Basic` and caching
// the converted pointer for subsequent requests.
func (s *OAS) getTykBasicAuth(name string) *Basic {
	return getTypedSchema[*Basic](s, name)
}

func (s *OAS) getTykOAuthAuth(name string) *OAuth {
	return getTypedSchema[*OAuth](s, name)
}

func (s *OAS) getTykExternalOAuthAuth(name string) *ExternalOAuth {
	return getTypedSchema[*ExternalOAuth](s, name)
}

func (s *OAS) getTykSecuritySchemes() (securitySchemes SecuritySchemes) {
	if s.getTykAuthentication() != nil {
		securitySchemes = s.getTykAuthentication().SecuritySchemes
	}

	return
}

func (s *OAS) getTykSecurityScheme(name string) interface{} {
	securitySchemes := s.getTykSecuritySchemes()

	ss, _ := securitySchemes.Get(name)
	return ss
}

// GetTykMiddleware returns middleware section from XTykAPIGateway.
func (s *OAS) GetTykMiddleware() (middleware *Middleware) {
	if extension := s.GetTykExtension(); extension != nil {
		middleware = extension.Middleware
	}

	return
}

func (s *OAS) getTykOperations() (operations Operations) {
	if s.GetTykMiddleware() != nil {
		operations = s.GetTykMiddleware().Operations
	}

	return
}

// RemoveServer removes the server from the server list if it's already present.
// It accepts regex-based server URLs, such as https://{subdomain:[a-z]+}.example.com/{version}
func (s *OAS) RemoveServer(serverUrl string) error {
	if len(serverUrl) == 0 {
		return nil
	}

	parsed, err := oasutil.ParseServerUrl(serverUrl)

	if err != nil {
		return err
	}

	s.Servers = lo.Filter(s.Servers, func(server *openapi3.Server, _ int) bool {
		return server.URL != parsed.UrlNormalized
	})

	return nil
}

// AddServers adds a server into the servers definition if not already present.
func (s *OAS) AddServers(apiURLs ...string) error {
	apiURLSet := make(map[string]struct{})
	var newServers openapi3.Servers

	for _, apiURL := range apiURLs {
		serverUrl, err := oasutil.ParseServerUrl(apiURL)

		if err != nil {
			return err
		}

		newServers = append(newServers, &openapi3.Server{
			URL:       serverUrl.UrlNormalized,
			Variables: serverUrl.Variables,
		})

		apiURLSet[apiURL] = struct{}{}
	}

	if len(newServers) == 0 {
		return nil
	}

	if len(s.Servers) == 0 {
		s.Servers = newServers
		return nil
	}

	// check if apiURL already exists in servers object
	for i := 0; i < len(s.Servers); i++ {
		if _, ok := apiURLSet[s.Servers[i].URL]; ok {
			continue
		}

		newServers = append(newServers, s.Servers[i])
	}

	s.Servers = newServers
	return nil
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

// Validate validates OAS document by calling openapi3.T.Validate() function. In addition, it validates Security
// Requirement section and it's requirements by calling OAS.validateSecurity() function.
func (s *OAS) Validate(ctx context.Context, opts ...openapi3.ValidationOption) error {
	validationErr := s.T.Validate(ctx, opts...)
	securityErr := s.validateSecurity()
	compliantModeErr := s.validateCompliantModeAuthentication()

	return errors.Join(validationErr, securityErr, compliantModeErr)
}

// Normalize converts the OAS api to a normalized state.
// it does this by fixing backwards compatibility issues
// and copying fields values necessary to work
// any logic to ensure the Tyk oas API is backwards compatible with previous versions of the gateway
// should be placed in here.
func (s *OAS) Normalize() {
	// copy the values of the new JWT validation
	jwtConfiguration := s.GetJWTConfiguration()
	if jwtConfiguration != nil {
		jwtConfiguration.Normalize()
	}
}

// validateSecurity verifies that existing Security Requirement Objects has Security Schemes declared in the Security
// Schemes under the Components Object. This function closes gap in validation provided by OAS.Validate func.
func (s *OAS) validateSecurity() error {
	if len(s.Security) == 0 {
		return nil
	}

	if s.Components == nil || s.Components.SecuritySchemes == nil || len(s.Components.SecuritySchemes) == 0 {
		return errors.New("No components or security schemes present in OAS")
	}

	for _, requirement := range s.Security {
		for key := range requirement {
			if _, ok := s.Components.SecuritySchemes[key]; !ok {
				errorMsg := fmt.Sprintf("Missing required Security Scheme '%s' in Components.SecuritySchemes. "+
					"For more information please visit https://swagger.io/specification/#security-requirement-object",
					key)
				return errors.New(errorMsg)
			}
		}
	}

	return nil
}

// validateCompliantModeAuthentication validates that all enabled auth methods in compliant mode
// are properly configured in security requirements (either OAS security or vendor extension security).
// This validation only runs when securityProcessingMode is set to "compliant".
func (s *OAS) validateCompliantModeAuthentication() error {
	tykAuth := s.getTykAuthentication()
	if tykAuth == nil {
		return nil
	}

	// Only validate in compliant mode
	if tykAuth.SecurityProcessingMode != SecurityProcessingModeCompliant {
		return nil
	}

	// Collect all security requirement names from both OAS and vendor extension
	configuredAuthMethods := make(map[string]bool)

	// Add OAS security requirements
	for _, requirement := range s.T.Security {
		for schemeName := range requirement {
			configuredAuthMethods[schemeName] = true
		}
	}

	// Add vendor extension security requirements
	if tykAuth.Security != nil {
		for _, requirement := range tykAuth.Security {
			for _, schemeName := range requirement {
				configuredAuthMethods[schemeName] = true
			}
		}
	}

	// Check each enabled auth method
	var misconfiguredMethods []string

	// Check top-level auth method fields (HMAC, OIDC, Custom)
	if tykAuth.HMAC != nil && tykAuth.HMAC.Enabled {
		if !configuredAuthMethods["hmac"] {
			misconfiguredMethods = append(misconfiguredMethods, "hmac")
		}
	}

	if tykAuth.OIDC != nil && tykAuth.OIDC.Enabled {
		if !configuredAuthMethods["oidc"] {
			misconfiguredMethods = append(misconfiguredMethods, "oidc")
		}
	}

	if tykAuth.Custom != nil && tykAuth.Custom.Enabled {
		if !configuredAuthMethods["custom"] {
			misconfiguredMethods = append(misconfiguredMethods, "custom")
		}
	}

	// Check auth methods in SecuritySchemes
	for schemeName, scheme := range tykAuth.SecuritySchemes.Iter() {
		// Check if this auth method is enabled
		enabled := false

		// Type-specific enabled checks
		switch v := scheme.(type) {
		case *Token:
			if v.Enabled != nil && *v.Enabled {
				enabled = true
			}
		case *JWT:
			if v.Enabled {
				enabled = true
			}
		case *Basic:
			if v.Enabled {
				enabled = true
			}
		case *OAuth:
			if v.Enabled {
				enabled = true
			}
		case *HMAC:
			if v.Enabled {
				enabled = true
			}
		case *OIDC:
			if v.Enabled {
				enabled = true
			}
		case *CustomPluginAuthentication:
			if v.Enabled {
				enabled = true
			}
		case map[string]interface{}:
			// Handle untyped schemes
			if enabledVal, ok := v["enabled"]; ok {
				if enabledBool, ok := enabledVal.(bool); ok && enabledBool {
					enabled = true
				}
			}
		}

		// If enabled but not in any security requirement, add to misconfigured list
		if enabled && !configuredAuthMethods[schemeName] {
			misconfiguredMethods = append(misconfiguredMethods, schemeName)
		}
	}

	// Return error if any misconfigured methods found
	if len(misconfiguredMethods) > 0 {
		methodList := strings.Join(misconfiguredMethods, " and ")
		var authWord string
		if len(misconfiguredMethods) == 1 {
			authWord = "auth"
		} else {
			authWord = "auth methods"
		}
		return fmt.Errorf("invalid multi-auth configuration: %s %s enabled but not configured in a security requirement", methodList, authWord)
	}

	return nil
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

	baseAPIDef.OAS, err = NewOASFromClassicAPIDefinition(api)
	if err != nil {
		return baseAPIDef, nil, fmt.Errorf("base API %s migrated OAS is not valid: %w", api.Name, err)
	}

	versionAPIDefs := make([]APIDef, len(versions))
	for i := 0; i < len(versions); i++ {
		versionOAS, err := NewOASFromClassicAPIDefinition(&versions[i])
		if err != nil {
			return baseAPIDef, nil, fmt.Errorf("version API %s migrated OAS is not valid: %w", versions[i].Name, err)
		}
		versionAPIDefs[i] = APIDef{versionOAS, &versions[i]}
	}

	return baseAPIDef, versionAPIDefs, err
}

func NewOASFromClassicAPIDefinition(api *apidef.APIDefinition) (*OAS, error) {
	var oas OAS
	return FillOASFromClassicAPIDefinition(api, &oas)
}

func FillOASFromClassicAPIDefinition(api *apidef.APIDefinition, oas *OAS) (*OAS, error) {
	api.IsOAS = true

	oas.Fill(*api)
	oas.setRequiredFields(api.Name, api.VersionName)
	clearClassicAPIForSomeFeatures(api)

	if err := oas.Validate(
		context.Background(),
		openapi3.DisableExamplesValidation(),
		openapi3.DisableSchemaDefaultsValidation(),
	); err != nil {
		return nil, err
	}

	b, err := oas.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return oas, ValidateOASObject(b, oas.OpenAPI)
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
	if len(api.VersionData.Versions) == 0 {
		return
	}

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
