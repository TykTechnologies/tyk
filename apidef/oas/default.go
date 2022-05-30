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
	invalidServerURLFmt          = "Please update %q to be a valid url or pass a valid url with upstreamURL query param"
	unsupportedSecuritySchemeFmt = "unsupported security scheme: %s"
	MiddlewareValidateRequest    = "validateRequest"
	MiddlewareAllowList          = "allowList"
)

var (
	errEmptyServersObject = errors.New("servers object is empty in OAS")
	errInvalidUpstreamURL = errors.New("invalid upstream URL")
	errInvalidServerURL   = errors.New("error validating servers entry in OAS")

	errEmptySecurityObject = errors.New("security object is empty in OAS")
	allowedMethods         = []string{
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

type TykExtensionConfigParams struct {
	UpstreamURL     string
	ListenPath      string
	CustomDomain    string
	ApiID           string
	Authentication  *bool
	AllowList       *bool
	ValidateRequest *bool
}

func (s *OAS) BuildDefaultTykExtension(overRideValues TykExtensionConfigParams) error {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway == nil {
		xTykAPIGateway = &XTykAPIGateway{}
		s.SetTykExtension(xTykAPIGateway)
	}

	if xTykAPIGateway.Info.Name == "" {
		xTykAPIGateway.Info.Name = s.Info.Title
	}

	if overRideValues.ApiID != "" {
		xTykAPIGateway.Info.ID = overRideValues.ApiID
	}

	xTykAPIGateway.Info.State.Active = true
	xTykAPIGateway.Info.State.Internal = false

	if overRideValues.ListenPath != "" {
		xTykAPIGateway.Server.ListenPath.Value = overRideValues.ListenPath
	} else if xTykAPIGateway.Server.ListenPath.Value == "" {
		xTykAPIGateway.Server.ListenPath.Value = "/"
	}

	if overRideValues.CustomDomain != "" {
		xTykAPIGateway.Server.CustomDomain = overRideValues.CustomDomain
	}

	var upstreamURL string

	if overRideValues.UpstreamURL != "" {
		upstreamURL = overRideValues.UpstreamURL
	} else {
		if len(s.Servers) == 0 {
			return errEmptyServersObject
		}

		upstreamURL = s.Servers[0].URL
	}

	if err := getURLFormatErr(overRideValues.UpstreamURL != "", upstreamURL); err != nil {
		return err
	}

	xTykAPIGateway.Upstream.URL = upstreamURL

	if overRideValues.Authentication != nil {
		err := s.importAuthentication(*overRideValues.Authentication)
		if err != nil {
			return err
		}
	}

	s.importMiddlewares(overRideValues.AllowList, overRideValues.ValidateRequest)

	return nil
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

	return nil
}

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

func (s *OAS) importMiddlewares(allowList, validateRequest *bool) {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway.Middleware == nil {
		xTykAPIGateway.Middleware = &Middleware{}
	}

	for path, pathItem := range s.Paths {
		for _, method := range allowedMethods {
			if operation := pathItem.GetOperation(method); operation != nil {
				tykOperation := s.getTykOperation(method, path)
				tykOperation.Import(operation, allowList, validateRequest)
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
		return fmt.Errorf("%w: %s", errInvalidServerURL, fmt.Sprintf(invalidServerURLFmt, parsedURL))
	}

	return nil
}

func GetTykExtensionConfigParams(r *http.Request) *TykExtensionConfigParams {
	queries := r.URL.Query()
	upstreamURL := strings.TrimSpace(queries.Get("upstreamURL"))
	listenPath := strings.TrimSpace(queries.Get("listenPath"))
	customDomain := strings.TrimSpace(queries.Get("customDomain"))
	apiID := strings.TrimSpace(queries.Get("apiID"))
	validateRequest := getQueryValPtr(strings.TrimSpace(queries.Get("validateRequest")))
	allowList := getQueryValPtr(strings.TrimSpace(queries.Get("allowList")))

	if upstreamURL == "" && listenPath == "" && customDomain == "" && apiID == "" &&
		validateRequest == nil && allowList == nil {
		return nil
	}

	return &TykExtensionConfigParams{
		UpstreamURL:     upstreamURL,
		ListenPath:      listenPath,
		CustomDomain:    customDomain,
		ValidateRequest: validateRequest,
		ApiID:           apiID,
		AllowList:       allowList,
	}
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
	if len(oldServers) > 0 && len(newServers) > 0 {
		if oldServers[0].URL == newServers[0].URL {
			return newServers
		}
		newServers = append(openapi3.Servers{oldServers[0]}, newServers...)
	}

	return newServers
}
