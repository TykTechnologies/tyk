package oas

import (
	"errors"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"net/http"
	"net/url"
	"strconv"
)

const (
	invalidServerURLFmt          = "Please update %q to be a valid url or pass a valid url with upstreamURL query param"
	unsupportedSecuritySchemeFmt = "unsupported security scheme: %s"
	MiddlewareValidateRequest    = "validateRequest"
	MiddlewareAllowList          = "allowList"
)

var (
	errEmptyServersObject  = errors.New("servers object is empty in OAS")
	errInvalidUpstreamURL  = errors.New("invalid upstream URL")
	errInvalidServerURL    = errors.New("error validating servers entry in OAS")
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
	if allowList != nil {
		s.importMiddleware(*allowList, MiddlewareAllowList)
	}

	if validateRequest != nil {
		s.importMiddleware(*validateRequest, MiddlewareValidateRequest)
	}

}

func (s *OAS) importMiddleware(enabled bool, middleware string) {
	for path, pathItem := range s.Paths {
		for _, method := range allowedMethods {
			if operation := pathItem.GetOperation(method); operation != nil {
				switch middleware {
				case MiddlewareAllowList:
					s.importAllowList(enabled, method, path)
				case MiddlewareValidateRequest:
					if shouldImport := shouldImportValidateRequest(operation); !shouldImport {
						continue
					}

					s.importValidateRequest(enabled, method, path)
				}
			}
		}

	}

}

func shouldImportValidateRequest(operation *openapi3.Operation) bool {
	reqBody := operation.RequestBody
	if reqBody == nil {
		return false
	}

	reqBodyVal := reqBody.Value
	if reqBodyVal == nil {
		return false
	}

	media := reqBodyVal.Content.Get("application/json")
	if media == nil {
		return false
	}

	return true
}

func (s *OAS) importAllowList(enabled bool, method, path string) {
	operation := s.getTykOperation(method, path)
	operation.Allow = &Allowance{
		Enabled: enabled,
	}

	if block := operation.Block; block != nil && block.Enabled && enabled {
		block.Enabled = false
	}

}

func (s *OAS) importValidateRequest(enabled bool, method, path string) {
	operation := s.getTykOperation(method, path)

	operation.ValidateRequest = &ValidateRequest{
		Enabled:           enabled,
		ErrorResponseCode: http.StatusBadRequest,
	}

}

func (s *OAS) getTykOperation(method, path string) *Operation {
	xTykAPIGateway := s.GetTykExtension()
	operationID := s.getOperationID(path, method)
	return xTykAPIGateway.getOperation(operationID)
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
	upstreamURL := r.URL.Query().Get("upstreamURL")
	listenPath := r.URL.Query().Get("listenPath")
	customDomain := r.URL.Query().Get("customDomain")

	validateRequest := getQueryValPtr(r.URL.Query().Get("validateRequest"))

	allowList := getQueryValPtr(r.URL.Query().Get("allowList"))

	if upstreamURL == "" && listenPath == "" && customDomain == "" &&
		validateRequest == nil && allowList == nil {
		return nil
	}

	return &TykExtensionConfigParams{
		UpstreamURL:     upstreamURL,
		ListenPath:      listenPath,
		CustomDomain:    customDomain,
		ValidateRequest: validateRequest,
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
