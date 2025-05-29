package oas

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	invalidServerURLFmt          = "Please update %q to be a valid URL and try again."
	unsupportedSecuritySchemeFmt = "unsupported security scheme: %s"

	middlewareValidateRequest = "validateRequest"
	middlewareAllowList       = "allowList"
	middlewareMockResponse    = "mockResponse"
)

var (
	errEmptyServersObject  = errors.New("The ‘servers’ object is empty in your OAS. You can either add a ‘servers’ section to your OpenAPI description or provide a Custom Upstream URL in the manual configuration options below.")
	errEmptySecurityObject = errors.New("The ‘security’ object is empty in your OAS. When enabling authentication, your OpenAPI description must include a ‘security’ object that defines the authentication schemes. You can either add a ‘security’ object or disable authentication in the API settings.")
	errInvalidUpstreamURL  = errors.New("The manually configured upstream URL is not valid. The URL must be absolute and properly formatted (e.g. https://example.com). Please check the URL format and try again.")
	errInvalidServerURL    = errors.New("The first entry in the ‘servers’ object of your OAS is not valid. The URL must be absolute and properly formatted (e.g. https://example.com).")

	allowedMethods = []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}
)

// TykExtensionConfigParams holds the essential configuration required for the Tyk Extension schema.
type TykExtensionConfigParams struct {
	// UpstreamURL configures the upstream URL.
	UpstreamURL string
	// ListenPath configures the listen path.
	ListenPath string
	// CustomDomain configures the domain name.
	CustomDomain string
	// ApiID is the API ID.
	ApiID string

	// Authentication is true if the API configures authentication.
	Authentication *bool
	// AllowList is true if the API configures an allow list.
	AllowList *bool
	// ValidateRequest is true if the API enables request validation.
	ValidateRequest *bool
	// MockResponse is true if a mocked response is configured.
	MockResponse *bool

	// pathItemHasParameters is set to true when parameters are defined the same level as of operations within path.
	pathItemHasParameters bool
}

// BuildDefaultTykExtension builds a default tyk extension in *OAS based on function arguments.
func (s *OAS) BuildDefaultTykExtension(overRideValues TykExtensionConfigParams, isImport bool) error {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway == nil {
		xTykAPIGateway = &XTykAPIGateway{}
		s.SetTykExtension(xTykAPIGateway)
	}

	if isImport {
		xTykAPIGateway.Info.State.Active = true
		xTykAPIGateway.Info.State.Internal = false
		xTykAPIGateway.Server.ListenPath.Strip = true
		xTykAPIGateway.enableContextVariablesIfEmpty()
		xTykAPIGateway.enableTrafficLogsIfEmpty()
	}

	if xTykAPIGateway.Info.Name == "" {
		xTykAPIGateway.Info.Name = s.Info.Title
	}

	if overRideValues.ApiID != "" {
		xTykAPIGateway.Info.ID = overRideValues.ApiID
	}

	if overRideValues.ListenPath != "" {
		xTykAPIGateway.Server.ListenPath.Value = overRideValues.ListenPath
	} else if xTykAPIGateway.Server.ListenPath.Value == "" {
		xTykAPIGateway.Server.ListenPath.Value = "/"
	}

	if overRideValues.CustomDomain != "" {
		if xTykAPIGateway.Server.CustomDomain == nil {
			xTykAPIGateway.Server.CustomDomain = &Domain{Enabled: true}
		}
		xTykAPIGateway.Server.CustomDomain.Name = overRideValues.CustomDomain
	}

	var upstreamURL string

	if overRideValues.UpstreamURL != "" {
		upstreamURL = overRideValues.UpstreamURL
	} else if xTykAPIGateway.Upstream.URL == "" {
		if len(s.Servers) == 0 {
			return errEmptyServersObject
		}

		upstreamURL = s.Servers[0].URL
		if isURLParametrized(upstreamURL) {
			var err error
			upstreamURL, err = generateUrlUsingDefaultVariableValues(s, upstreamURL)
			if err != nil {
				return err
			}
		}
	}

	if upstreamURL != "" {
		if err := getURLFormatErr(overRideValues.UpstreamURL != "", upstreamURL); err != nil {
			return err
		}

		xTykAPIGateway.Upstream.URL = upstreamURL
	}

	if overRideValues.Authentication != nil {
		err := s.importAuthentication(*overRideValues.Authentication)
		if err != nil {
			return err
		}
	}

	s.importMiddlewares(overRideValues)

	return nil
}

func generateUrlUsingDefaultVariableValues(s *OAS, upstreamURL string) (string, error) {
	for name, variable := range s.Servers[0].Variables {
		if strings.Contains(upstreamURL, "{"+name+"}") {
			if variable.Default == "" {
				return "", fmt.Errorf("server variable %s does not have a default value", name)
			}
			upstreamURL = replaceParameterWithValue(upstreamURL, name, variable.Default)
		}
	}
	if isURLParametrized(upstreamURL) {
		return "", errors.New("server URL contains undefined variables")
	}
	return upstreamURL, nil
}

func isURLParametrized(url string) bool {
	return strings.Contains(url, "{") && strings.Contains(url, "}")
}

func replaceParameterWithValue(url string, name string, value string) string {
	return strings.ReplaceAll(url, "{"+name+"}", value)
}

func (s *OAS) importAuthentication(enable bool) error {
	if len(s.Security) == 0 {
		return errEmptySecurityObject
	}

	securityReq := s.Security[0]

	xTykAPIGateway := s.GetTykExtension()
	authentication := xTykAPIGateway.Server.Authentication
	if authentication == nil {
		authentication = &Authentication{}
		xTykAPIGateway.Server.Authentication = authentication
	}

	authentication.Enabled = enable

	tykSecuritySchemes := authentication.SecuritySchemes
	if tykSecuritySchemes == nil {
		tykSecuritySchemes = make(SecuritySchemes)
		authentication.SecuritySchemes = tykSecuritySchemes
	}

	for name := range securityReq {
		securityScheme := s.Components.SecuritySchemes[name]
		err := tykSecuritySchemes.Import(name, securityScheme.Value, enable)
		if err != nil {
			log.WithError(err).Errorf("Error while importing security scheme: %s", name)
		}
	}

	authentication.BaseIdentityProvider = tykSecuritySchemes.GetBaseIdentityProvider()

	return nil
}

// Import populates *AuthSources based on arguments.
func (as *AuthSources) Import(in string) {
	source := &AuthSource{Enabled: true}

	switch in {
	case header:
		as.Header = source
	case cookie:
		as.Cookie = source
	case query:
		as.Query = source
	}
}

func (s *OAS) importMiddlewares(overRideValues TykExtensionConfigParams) {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway.Middleware == nil {
		xTykAPIGateway.Middleware = &Middleware{}
	}

	for path, pathItem := range s.Paths.Map() {
		overRideValues.pathItemHasParameters = len(pathItem.Parameters) > 0
		for _, method := range allowedMethods {
			if operation := pathItem.GetOperation(method); operation != nil {
				tykOperation := s.getTykOperation(method, path)
				tykOperation.Import(operation, overRideValues)
				s.deleteTykOperationIfEmpty(tykOperation, method, path)
			}
		}
	}

	if ShouldOmit(xTykAPIGateway.Middleware) {
		xTykAPIGateway.Middleware = nil
	}
}

func (s *OAS) getTykOperation(method, path string) *Operation {
	xTykAPIGateway := s.GetTykExtension()
	operationID := s.getOperationID(path, method)
	return xTykAPIGateway.getOperation(operationID)
}

func (s *OAS) deleteTykOperationIfEmpty(tykOperation *Operation, method, path string) {
	if reflect.DeepEqual(Operation{}, *tykOperation) {
		operations := s.getTykOperations()
		operationID := s.getOperationID(path, method)
		delete(operations, operationID)
	}
}

func getURLFormatErr(fromParam bool, upstreamURL string) error {
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil || !parsedURL.IsAbs() {
		if fromParam {
			return errInvalidUpstreamURL
		}
		return fmt.Errorf("%w %s", errInvalidServerURL, fmt.Sprintf(invalidServerURLFmt, parsedURL))
	}

	return nil
}

// GetTykExtensionConfigParams extracts a *TykExtensionConfigParams from a *http.Request.
func GetTykExtensionConfigParams(r *http.Request) *TykExtensionConfigParams {
	overRideValues := TykExtensionConfigParams{}

	queries := r.URL.Query()
	overRideValues.UpstreamURL = strings.TrimSpace(queries.Get("upstreamURL"))
	overRideValues.ListenPath = strings.TrimSpace(queries.Get("listenPath"))
	overRideValues.CustomDomain = strings.TrimSpace(queries.Get("customDomain"))
	overRideValues.ApiID = strings.TrimSpace(queries.Get("apiID"))

	overRideValues.Authentication = getQueryValPtr(strings.TrimSpace(queries.Get("authentication")))
	overRideValues.ValidateRequest = getQueryValPtr(strings.TrimSpace(queries.Get("validateRequest")))
	overRideValues.AllowList = getQueryValPtr(strings.TrimSpace(queries.Get("allowList")))
	overRideValues.MockResponse = getQueryValPtr(strings.TrimSpace(queries.Get("mockResponse")))

	if ShouldOmit(overRideValues) {
		return nil
	}

	return &overRideValues
}

func getQueryValPtr(val string) *bool {
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return nil
	}

	return &boolVal
}

// RetainOldServerURL retains the first entry from old servers provided
// tyk adds a server URL to the start of oas.Servers to add the gw URL
// RetainOldServerURL can be used when API def is patched.
func RetainOldServerURL(oldServers, newServers openapi3.Servers) openapi3.Servers {
	// If there are no new servers, return nil
	// This ensures empty server lists are properly represented
	if len(newServers) == 0 {
		return oldServers
	}

	// If there are no old servers, return the new ones
	if len(oldServers) == 0 {
		return newServers
	}

	// Always keep the first entry from oldServers
	first := oldServers[0]

	// Check if the first server is already in the new servers list
	alreadyExists := false
	for _, server := range newServers {
		if strings.TrimSpace(server.URL) == strings.TrimSpace(first.URL) {
			alreadyExists = true
			break
		}
	}

	// If first server already exists in newServers, return newServers
	if alreadyExists {
		return newServers
	}

	// Otherwise, prepend the first old server to newServers
	return append(openapi3.Servers{first}, newServers...)
}
