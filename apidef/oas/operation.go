package oas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/oasutil"
)

// Operations holds Operation definitions.
type Operations map[string]*Operation

// Operation holds a request operation configuration, allowances, tranformations, caching, timeouts and validation.
type Operation struct {
	// Allow request by allowance.
	Allow *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block request by allowance.
	Block *Allowance `bson:"block,omitempty" json:"block,omitempty"`

	// IgnoreAuthentication ignores authentication on request by allowance.
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`

	// Internal makes the endpoint only respond to internal requests.
	Internal *Internal `bson:"internal,omitempty" json:"internal,omitempty"`

	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`

	// TransformRequestBody allows you to transform request body.
	// When both `path` and `body` are provided, body would take precedence.
	TransformRequestBody *TransformBody `bson:"transformRequestBody,omitempty" json:"transformRequestBody,omitempty"`

	// TransformResponseBody allows you to transform response body.
	// When both `path` and `body` are provided, body would take precedence.
	TransformResponseBody *TransformBody `bson:"transformResponseBody,omitempty" json:"transformResponseBody,omitempty"`

	// TransformRequestHeaders allows you to transform request headers.
	TransformRequestHeaders *TransformHeaders `bson:"transformRequestHeaders,omitempty" json:"transformRequestHeaders,omitempty"`

	// TransformResponseHeaders allows you to transform response headers.
	TransformResponseHeaders *TransformHeaders `bson:"transformResponseHeaders,omitempty" json:"transformResponseHeaders,omitempty"`

	// URLRewrite contains the URL rewriting configuration.
	URLRewrite *URLRewrite `bson:"urlRewrite,omitempty" json:"urlRewrite,omitempty"`

	// Cache contains the caching plugin configuration.
	Cache *CachePlugin `bson:"cache,omitempty" json:"cache,omitempty"`

	// EnforceTimeout contains the request timeout configuration.
	EnforceTimeout *EnforceTimeout `bson:"enforceTimeout,omitempty" json:"enforceTimeout,omitempty"`

	// ValidateRequest contains the request validation configuration.
	ValidateRequest *ValidateRequest `bson:"validateRequest,omitempty" json:"validateRequest,omitempty"`

	// MockResponse contains the mock response configuration.
	MockResponse *MockResponse `bson:"mockResponse,omitempty" json:"mockResponse,omitempty"`

	// VirtualEndpoint contains virtual endpoint configuration.
	VirtualEndpoint *VirtualEndpoint `bson:"virtualEndpoint,omitempty" json:"virtualEndpoint,omitempty"`

	// PostPlugins contains endpoint level post plugins configuration.
	PostPlugins EndpointPostPlugins `bson:"postPlugins,omitempty" json:"postPlugins,omitempty"`

	// CircuitBreaker contains the configuration for the circuit breaker functionality.
	CircuitBreaker *CircuitBreaker `bson:"circuitBreaker,omitempty" json:"circuitBreaker,omitempty"`

	// TrackEndpoint contains the configuration for enabling analytics and logs.
	TrackEndpoint *TrackEndpoint `bson:"trackEndpoint,omitempty" json:"trackEndpoint,omitempty"`

	// DoNotTrackEndpoint contains the configuration for disabling analytics and logs.
	DoNotTrackEndpoint *TrackEndpoint `bson:"doNotTrackEndpoint,omitempty" json:"doNotTrackEndpoint,omitempty"`

	// RequestSizeLimit limits the maximum allowed size of the request body in bytes.
	RequestSizeLimit *RequestSizeLimit `bson:"requestSizeLimit,omitempty" json:"requestSizeLimit,omitempty"`

	// RateLimit contains endpoint level rate limit configuration.
	RateLimit *RateLimitEndpoint `bson:"rateLimit,omitempty" json:"rateLimit,omitempty"`
}

// AllowanceType holds the valid allowance types values.
type AllowanceType int

const (
	allow                AllowanceType = 0
	block                AllowanceType = 1
	ignoreAuthentication AllowanceType = 2

	contentTypeJSON = "application/json"
)

// Import takes the arguments and populates the receiver *Operation values.
func (o *Operation) Import(oasOperation *openapi3.Operation, overRideValues TykExtensionConfigParams) {
	if overRideValues.AllowList != nil {
		allow := o.Allow
		if allow == nil {
			allow = &Allowance{}
		}

		allow.Import(*overRideValues.AllowList)

		if block := o.Block; block != nil && block.Enabled && *overRideValues.AllowList {
			block.Enabled = false
		}

		o.Allow = allow
	}

	if overRideValues.ValidateRequest != nil {
		validate := o.ValidateRequest
		if validate == nil {
			validate = &ValidateRequest{}
		}

		if ok := validate.shouldImport(oasOperation); ok || overRideValues.pathItemHasParameters {
			validate.Import(*overRideValues.ValidateRequest)
			o.ValidateRequest = validate
		}
	}

	if overRideValues.MockResponse != nil {
		mock := o.MockResponse
		if mock == nil {
			mock = &MockResponse{}
		}

		if ok := mock.shouldImport(oasOperation); ok {
			mock.Import(*overRideValues.MockResponse)
			o.MockResponse = mock
		}
	}
}

func (s *OAS) fillPathsAndOperations(ep apidef.ExtendedPathsSet) {
	// Regardless if `ep` is a zero value, we need a non-nil paths
	// to produce a valid OAS document
	if s.Paths == nil {
		s.Paths = make(openapi3.Paths)
	}

	s.fillAllowance(ep.WhiteList, allow)
	s.fillAllowance(ep.BlackList, block)
	s.fillAllowance(ep.Ignored, ignoreAuthentication)
	s.fillTransformRequestMethod(ep.MethodTransforms)
	s.fillTransformRequestBody(ep.Transform)
	s.fillTransformResponseBody(ep.TransformResponse)
	s.fillTransformRequestHeaders(ep.TransformHeader)
	s.fillTransformResponseHeaders(ep.TransformResponseHeader)
	s.fillURLRewrite(ep.URLRewrite)
	s.fillInternal(ep.Internal)
	s.fillCache(ep.AdvanceCacheConfig)
	s.fillEnforceTimeout(ep.HardTimeouts)
	s.fillOASValidateRequest(ep.ValidateJSON)
	s.fillVirtualEndpoint(ep.Virtual)
	s.fillEndpointPostPlugins(ep.GoPlugin)
	s.fillCircuitBreaker(ep.CircuitBreaker)
	s.fillTrackEndpoint(ep.TrackEndpoints)
	s.fillDoNotTrackEndpoint(ep.DoNotTrackEndpoints)
	s.fillRequestSizeLimit(ep.SizeLimit)
	s.fillRateLimitEndpoints(ep.RateLimit)
	s.fillMockResponsePaths(s.Paths, ep)
}

// fillMockResponsePaths converts classic API mock responses to OAS format.
// For each mock response, it:
// 1. Creates an OAS operation with a unique ID (method + path + status code)
// 2. Sets up the mock response with content type detection and example values
// 3. Configures the operation to ignore authentication for this endpoint
func (s *OAS) fillMockResponsePaths(paths openapi3.Paths, ep apidef.ExtendedPathsSet) {
	var methodOperationMap = map[string]func(*openapi3.PathItem, *openapi3.Operation){
		http.MethodGet:     func(p *openapi3.PathItem, op *openapi3.Operation) { p.Get = op },
		http.MethodPost:    func(p *openapi3.PathItem, op *openapi3.Operation) { p.Post = op },
		http.MethodPut:     func(p *openapi3.PathItem, op *openapi3.Operation) { p.Put = op },
		http.MethodPatch:   func(p *openapi3.PathItem, op *openapi3.Operation) { p.Patch = op },
		http.MethodDelete:  func(p *openapi3.PathItem, op *openapi3.Operation) { p.Delete = op },
		http.MethodHead:    func(p *openapi3.PathItem, op *openapi3.Operation) { p.Head = op },
		http.MethodOptions: func(p *openapi3.PathItem, op *openapi3.Operation) { p.Options = op },
	}

	for _, mock := range ep.MockResponse {
		pathItem := paths[mock.Path]
		if pathItem == nil {
			pathItem = &openapi3.PathItem{}
			paths[mock.Path] = pathItem
		}

		operation := &openapi3.Operation{
			Responses: openapi3.NewResponses(),
		}

		operation.OperationID = genMockResponseOperationID(mock)

		// Response description is required by the OAS spec, but we don't have it in Tyk classic.
		// So we're using a dummy value to satisfy the spec.
		dummyDescription := "CHANGE ME"

		response := &openapi3.Response{
			Headers:     make(openapi3.Headers),
			Description: &dummyDescription,
		}

		contentType := "text/plain"

		for name, value := range mock.Headers {
			if http.CanonicalHeaderKey(name) == "Content-Type" {
				contentType = value
				break
			}
		}

		// We attempt to guess the content type by checking if the body is a valid JSON.
		if mock.Body != "" {
			var body json.RawMessage
			if err := json.Unmarshal([]byte(mock.Body), &body); err == nil {
				contentType = "application/json"
			}
		}

		mediaType := &openapi3.MediaType{
			Examples: openapi3.Examples{
				"default": &openapi3.ExampleRef{
					Value: &openapi3.Example{
						Value: mock.Body,
					},
				},
			},
		}

		response.Content = openapi3.Content{
			contentType: mediaType,
		}

		for name, value := range mock.Headers {
			response.Headers[http.CanonicalHeaderKey(name)] = &openapi3.HeaderRef{
				Value: &openapi3.Header{
					Parameter: openapi3.Parameter{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type:    "string",
								Example: value,
							},
						},
					},
				},
			}
		}

		operation.Responses[strconv.Itoa(mock.Code)] = &openapi3.ResponseRef{
			Value: response,
		}

		if setOperation, exists := methodOperationMap[mock.Method]; exists {
			setOperation(pathItem, operation)
		}

		tykOperation := s.GetTykExtension().getOperation(operation.OperationID)
		if tykOperation == nil {
			tykOperation = &Operation{}
			s.GetTykExtension().Middleware.Operations[operation.OperationID] = tykOperation
		}

		if tykOperation.MockResponse == nil {
			tykOperation.MockResponse = &MockResponse{}
		}

		if tykOperation.IgnoreAuthentication == nil {
			tykOperation.IgnoreAuthentication = &Allowance{Enabled: true}
		}

		tykOperation.MockResponse.Fill(mock)
	}
}

func (s *OAS) extractPathsAndOperations(ep *apidef.ExtendedPathsSet) {
	ep.Clear()

	tykOperations := s.getTykOperations()
	if len(tykOperations) == 0 {
		return
	}

	for _, pathItem := range oasutil.SortByPathLength(s.Paths) {
		for id, tykOp := range tykOperations {
			path := pathItem.Path
			for method, operation := range pathItem.Operations() {
				if id == operation.OperationID {
					tykOp.extractAllowanceTo(ep, path, method, allow)
					tykOp.extractAllowanceTo(ep, path, method, block)
					tykOp.extractAllowanceTo(ep, path, method, ignoreAuthentication)
					tykOp.extractInternalTo(ep, path, method)
					tykOp.extractTransformRequestMethodTo(ep, path, method)
					tykOp.extractTransformRequestBodyTo(ep, path, method)
					tykOp.extractTransformResponseBodyTo(ep, path, method)
					tykOp.extractTransformRequestHeadersTo(ep, path, method)
					tykOp.extractTransformResponseHeadersTo(ep, path, method)
					tykOp.extractURLRewriteTo(ep, path, method)
					tykOp.extractCacheTo(ep, path, method)
					tykOp.extractEnforceTimeoutTo(ep, path, method)
					tykOp.extractVirtualEndpointTo(ep, path, method)
					tykOp.extractEndpointPostPluginTo(ep, path, method)
					tykOp.extractCircuitBreakerTo(ep, path, method)
					tykOp.extractTrackEndpointTo(ep, path, method)
					tykOp.extractDoNotTrackEndpointTo(ep, path, method)
					tykOp.extractRequestSizeLimitTo(ep, path, method)
					tykOp.extractRateLimitEndpointTo(ep, path, method)
					tykOp.extractMockResponsePaths(ep, path, method)
					break
				}
			}
		}
	}

	// Sort the mock response paths by path, method, and response code.
	// This ensures a deterministic order of mock responses.
	sort.Slice(ep.MockResponse, func(i, j int) bool {
		// First sort by path
		if ep.MockResponse[i].Path != ep.MockResponse[j].Path {
			return ep.MockResponse[i].Path < ep.MockResponse[j].Path
		}
		// Then by method
		if ep.MockResponse[i].Method != ep.MockResponse[j].Method {
			return ep.MockResponse[i].Method < ep.MockResponse[j].Method
		}
		// Finally by response code
		return ep.MockResponse[i].Code < ep.MockResponse[j].Code
	})
}

func (s *OAS) fillAllowance(endpointMetas []apidef.EndPointMeta, typ AllowanceType) {
	for _, em := range endpointMetas {
		operationID := s.getOperationID(em.Path, em.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		var allowance *Allowance

		switch typ {
		case block:
			allowance = newAllowance(&operation.Block)
		case ignoreAuthentication:
			allowance = newAllowance(&operation.IgnoreAuthentication)
		default:
			allowance = newAllowance(&operation.Allow)
		}

		allowance.Fill(em)
		if ShouldOmit(allowance) {
			allowance = nil
		}
	}
}

func newAllowance(prev **Allowance) *Allowance {
	if *prev == nil {
		*prev = &Allowance{}
	}

	return *prev
}

func (s *OAS) fillTransformRequestMethod(metas []apidef.MethodTransformMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.TransformRequestMethod == nil {
			operation.TransformRequestMethod = &TransformRequestMethod{}
		}

		operation.TransformRequestMethod.Fill(meta)
		if ShouldOmit(operation.TransformRequestMethod) {
			operation.TransformRequestMethod = nil
		}
	}
}

func (s *OAS) fillTransformRequestBody(metas []apidef.TemplateMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.TransformRequestBody == nil {
			operation.TransformRequestBody = &TransformBody{}
		}

		operation.TransformRequestBody.Fill(meta)
		if ShouldOmit(operation.TransformRequestBody) {
			operation.TransformRequestBody = nil
		}
	}
}

func (s *OAS) fillTransformResponseBody(metas []apidef.TemplateMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.TransformResponseBody == nil {
			operation.TransformResponseBody = &TransformBody{}
		}

		operation.TransformResponseBody.Fill(meta)
		if ShouldOmit(operation.TransformResponseBody) {
			operation.TransformResponseBody = nil
		}
	}
}

func (s *OAS) fillTransformRequestHeaders(metas []apidef.HeaderInjectionMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.TransformRequestHeaders == nil {
			operation.TransformRequestHeaders = &TransformHeaders{}
		}

		operation.TransformRequestHeaders.Fill(meta)
		if ShouldOmit(operation.TransformRequestHeaders) {
			operation.TransformRequestHeaders = nil
		}
	}
}

func (s *OAS) fillTransformResponseHeaders(metas []apidef.HeaderInjectionMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		if operation.TransformResponseHeaders == nil {
			operation.TransformResponseHeaders = &TransformHeaders{}
		}

		operation.TransformResponseHeaders.Fill(meta)
		if ShouldOmit(operation.TransformResponseHeaders) {
			operation.TransformResponseHeaders = nil
		}
	}
}

func (s *OAS) fillCache(metas []apidef.CacheMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.Cache == nil {
			operation.Cache = &CachePlugin{}
		}

		operation.Cache.Fill(meta)
		if ShouldOmit(operation.Cache) {
			operation.Cache = nil
		}
	}
}

func (s *OAS) fillEnforceTimeout(metas []apidef.HardTimeoutMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.EnforceTimeout == nil {
			operation.EnforceTimeout = &EnforceTimeout{}
		}

		operation.EnforceTimeout.Fill(meta)
		if ShouldOmit(operation.EnforceTimeout) {
			operation.EnforceTimeout = nil
		}
	}
}

func (s *OAS) fillRequestSizeLimit(metas []apidef.RequestSizeMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.RequestSizeLimit == nil {
			operation.RequestSizeLimit = &RequestSizeLimit{}
		}

		operation.RequestSizeLimit.Fill(meta)
		if ShouldOmit(operation.RequestSizeLimit) {
			operation.RequestSizeLimit = nil
		}
	}
}

func (o *Operation) extractAllowanceTo(ep *apidef.ExtendedPathsSet, path string, method string, typ AllowanceType) {
	allowance := o.Allow
	endpointMetas := &ep.WhiteList

	switch typ {
	case block:
		allowance = o.Block
		endpointMetas = &ep.BlackList
	case ignoreAuthentication:
		allowance = o.IgnoreAuthentication
		endpointMetas = &ep.Ignored
	}

	if allowance == nil {
		return
	}

	endpointMeta := apidef.EndPointMeta{Path: path, Method: method}
	allowance.ExtractTo(&endpointMeta)
	*endpointMetas = append(*endpointMetas, endpointMeta)
}

func (o *Operation) extractTransformRequestMethodTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TransformRequestMethod == nil {
		return
	}

	meta := apidef.MethodTransformMeta{Path: path, Method: method}
	o.TransformRequestMethod.ExtractTo(&meta)
	ep.MethodTransforms = append(ep.MethodTransforms, meta)
}

func (o *Operation) extractTransformRequestBodyTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TransformRequestBody == nil {
		return
	}

	meta := apidef.TemplateMeta{Path: path, Method: method}
	o.TransformRequestBody.ExtractTo(&meta)
	ep.Transform = append(ep.Transform, meta)
}

func (o *Operation) extractTransformResponseBodyTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TransformResponseBody == nil {
		return
	}

	meta := apidef.TemplateMeta{Path: path, Method: method}
	o.TransformResponseBody.ExtractTo(&meta)
	ep.TransformResponse = append(ep.TransformResponse, meta)
}

func (o *Operation) extractTransformRequestHeadersTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TransformRequestHeaders == nil {
		return
	}

	meta := apidef.HeaderInjectionMeta{Path: path, Method: method}
	o.TransformRequestHeaders.ExtractTo(&meta)
	ep.TransformHeader = append(ep.TransformHeader, meta)
}

func (o *Operation) extractTransformResponseHeadersTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.TransformResponseHeaders == nil {
		return
	}

	meta := apidef.HeaderInjectionMeta{Path: path, Method: method}
	o.TransformResponseHeaders.ExtractTo(&meta)
	ep.TransformResponseHeader = append(ep.TransformResponseHeader, meta)
}

func (o *Operation) extractCacheTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.Cache == nil {
		return
	}

	newCacheMeta := apidef.CacheMeta{
		Method: method,
		Path:   path,
	}
	o.Cache.ExtractTo(&newCacheMeta)
	ep.AdvanceCacheConfig = append(ep.AdvanceCacheConfig, newCacheMeta)
}

func (o *Operation) extractEnforceTimeoutTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.EnforceTimeout == nil {
		return
	}

	meta := apidef.HardTimeoutMeta{Path: path, Method: method}
	o.EnforceTimeout.ExtractTo(&meta)
	ep.HardTimeouts = append(ep.HardTimeouts, meta)
}

func (o *Operation) extractRequestSizeLimitTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.RequestSizeLimit == nil {
		return
	}

	meta := apidef.RequestSizeMeta{Path: path, Method: method}
	o.RequestSizeLimit.ExtractTo(&meta)
	ep.SizeLimit = append(ep.SizeLimit, meta)
}

// extractMockResponsePaths converts OAS mock responses to classic API format.
// For each mock response, it:
// 1. Creates a classic API whitelist entry with the mock response configuration
// 2. Sets up the response code, body and headers
// 3. Configures the endpoint to use the Reply action
func (o *Operation) extractMockResponsePaths(ep *apidef.ExtendedPathsSet, path, method string) {
	if o.MockResponse == nil {
		return
	}

	headers := make(map[string]string)

	for _, header := range o.MockResponse.Headers {
		headers[header.Name] = header.Value
	}

	if ep.WhiteList == nil {
		ep.WhiteList = make([]apidef.EndPointMeta, 0)
	}

	wl := apidef.EndPointMeta{
		Disabled: !o.MockResponse.Enabled,
		Path:     path,
		Method:   method,
	}

	wl.MethodActions = make(map[string]apidef.EndpointMethodMeta)

	wl.MethodActions[method] = apidef.EndpointMethodMeta{
		Action:  apidef.Reply,
		Code:    o.MockResponse.Code,
		Data:    o.MockResponse.Body,
		Headers: headers,
	}

	ep.WhiteList = append(ep.WhiteList, wl)
}

// detect possible regex pattern:
// - character match ([a-z])
// - greedy match (.*)
// - ungreedy match (.+)
// - end of string ($).
var regexPatterns = []string{
	".+", ".*", "[", "]", "$",
}

type pathPart struct {
	name    string
	value   string
	isRegex bool
}

func (p pathPart) String() string {
	if p.isRegex {
		return "{" + p.name + "}"
	}

	return p.value
}

// isRegex checks if value has expected regular expression patterns.
func isRegex(value string) bool {
	for _, pattern := range regexPatterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}

// splitPath splits URL into folder parts, detecting regex patterns.
func splitPath(inPath string) ([]pathPart, bool) {
	// Each URL fragment can contain a regex, but the whole
	// URL isn't just a regex (`/a/.*/foot` => `/a/{param1}/foot`)
	parts := strings.Split(strings.Trim(inPath, "/"), "/")
	result := make([]pathPart, len(parts))
	found := 0

	for k, value := range parts {
		name := value
		isRegex := isRegex(value)
		if isRegex {
			found++
			name = fmt.Sprintf("customRegex%d", found)
		}
		result[k] = pathPart{
			name:    name,
			value:   value,
			isRegex: isRegex,
		}
	}

	return result, found > 0
}

// buildPath converts the URL paths with regex to named parameters
// e.g. ["a", ".*"] becomes /a/{customRegex1}.
func buildPath(parts []pathPart, appendSlash bool) string {
	newPath := ""

	for _, part := range parts {
		newPath += "/" + part.String()
	}

	if appendSlash {
		return newPath + "/"
	}

	return newPath
}

func (s *OAS) getOperationID(inPath, method string) string {
	operationID := strings.TrimPrefix(inPath, "/") + method

	createOrGetPathItem := func(item string) *openapi3.PathItem {
		if s.Paths[item] == nil {
			s.Paths[item] = &openapi3.PathItem{}
		}

		return s.Paths[item]
	}

	createOrUpdateOperation := func(p *openapi3.PathItem) *openapi3.Operation {
		operation := p.GetOperation(method)

		if operation == nil {
			operation = &openapi3.Operation{
				Responses: openapi3.NewResponses(),
			}
			p.SetOperation(method, operation)
		}

		if operation.OperationID == "" {
			operation.OperationID = operationID
		}

		return operation
	}

	var p *openapi3.PathItem
	parts, hasRegex := splitPath(inPath)

	if hasRegex {
		newPath := buildPath(parts, strings.HasSuffix(inPath, "/"))

		p = createOrGetPathItem(newPath)
		p.Parameters = []*openapi3.ParameterRef{}

		for _, part := range parts {
			if part.isRegex {
				schema := &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type:    "string",
						Pattern: part.value,
					},
				}
				param := &openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     part.name,
						In:       "path",
						Required: true,
						Schema:   schema,
					},
				}
				p.Parameters = append(p.Parameters, param)
			}
		}
	} else {
		p = createOrGetPathItem(inPath)
	}

	operation := createOrUpdateOperation(p)
	return operation.OperationID
}

func (x *XTykAPIGateway) getOperation(operationID string) *Operation {
	if x.Middleware == nil {
		x.Middleware = &Middleware{}
	}

	middleware := x.Middleware

	if middleware.Operations == nil {
		middleware.Operations = make(Operations)
	}

	operations := middleware.Operations

	if operations[operationID] == nil {
		operations[operationID] = &Operation{}
	}

	return operations[operationID]
}

// ValidateRequest holds configuration required for validating requests.
type ValidateRequest struct {
	// Enabled is a boolean flag, if set to `true`, it enables request validation.
	Enabled bool `bson:"enabled" json:"enabled"`

	// ErrorResponseCode is the error code emitted when the request fails validation.
	// If unset or zero, the response will returned with http status 422 Unprocessable Entity.
	ErrorResponseCode int `bson:"errorResponseCode,omitempty" json:"errorResponseCode,omitempty"`
}

// Fill fills *ValidateRequest receiver from apidef.ValidateRequestMeta.
func (v *ValidateRequest) Fill(meta apidef.ValidatePathMeta) {
	v.Enabled = !meta.Disabled
	v.ErrorResponseCode = meta.ErrorResponseCode
}

func (*ValidateRequest) shouldImport(operation *openapi3.Operation) bool {
	if len(operation.Parameters) > 0 {
		return true
	}

	reqBody := operation.RequestBody
	if reqBody == nil {
		return false
	}

	reqBodyVal := reqBody.Value
	if reqBodyVal == nil {
		return false
	}

	media := reqBodyVal.Content.Get("application/json")

	return media != nil
}

// Import populates *ValidateRequest with enabled argument and a default error response code.
func (v *ValidateRequest) Import(enabled bool) {
	v.Enabled = enabled
	v.ErrorResponseCode = http.StatusUnprocessableEntity
}

func convertSchema(mapSchema map[string]interface{}) (*openapi3.Schema, error) {
	bytes, err := json.Marshal(mapSchema)
	if err != nil {
		return nil, err
	}

	schema := openapi3.NewSchema()
	err = schema.UnmarshalJSON(bytes)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

func (s *OAS) fillOASValidateRequest(metas []apidef.ValidatePathMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)

		operation := s.Paths.Find(meta.Path).GetOperation(meta.Method)
		requestBodyRef := operation.RequestBody
		if operation.RequestBody == nil {
			requestBodyRef = &openapi3.RequestBodyRef{}
			operation.RequestBody = requestBodyRef
		}

		if requestBodyRef.Value == nil {
			requestBodyRef.Value = openapi3.NewRequestBody()
		}

		schema, err := convertSchema(meta.Schema)
		if err != nil {
			log.WithError(err).Error("Couldn't convert classic API validate JSON schema to OAS")
		} else {
			requestBodyRef.Value.WithJSONSchema(schema)
		}

		tykOp := s.GetTykExtension().getOperation(operationID)

		if tykOp.ValidateRequest == nil {
			tykOp.ValidateRequest = &ValidateRequest{}
		}

		tykOp.ValidateRequest.Fill(meta)

		if ShouldOmit(tykOp.ValidateRequest) {
			tykOp.ValidateRequest = nil
		}
	}
}

// MockResponse configures the mock responses.
type MockResponse struct {
	// Enabled activates the mock response middleware.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Code is the HTTP response code that will be returned.
	Code int `bson:"code,omitempty" json:"code,omitempty"`
	// Body is the HTTP response body that will be returned.
	Body string `bson:"body,omitempty" json:"body,omitempty"`
	// Headers are the HTTP response headers that will be returned.
	Headers Headers `bson:"headers,omitempty" json:"headers,omitempty"`
	// FromOASExamples is the configuration to extract a mock response from OAS documentation.
	FromOASExamples *FromOASExamples `bson:"fromOASExamples,omitempty" json:"fromOASExamples,omitempty"`
}

// Fill populates the MockResponse fields from a classic API MockResponseMeta.
func (m *MockResponse) Fill(op apidef.MockResponseMeta) {
	headers := make([]Header, 0)
	for k, v := range op.Headers {
		headers = append(headers, Header{
			Name:  http.CanonicalHeaderKey(k),
			Value: v,
		})
	}

	// Sort headers by name so that the order is deterministic
	sort.Slice(headers, func(i, j int) bool {
		return headers[i].Name < headers[j].Name
	})

	m.Enabled = !op.Disabled
	m.Code = op.Code
	m.Body = op.Body
	m.Headers = headers
}

func (m *MockResponse) ExtractTo(meta *apidef.MockResponseMeta) {
	meta.Disabled = !m.Enabled
	meta.Code = m.Code
	meta.Body = m.Body

	// Initialize headers map even when empty
	meta.Headers = make(map[string]string)

	for _, h := range m.Headers {
		meta.Headers[h.Name] = h.Value
	}

	if len(meta.Headers) == 0 {
		meta.Headers = nil
	}
}

// FromOASExamples configures mock responses that should be returned from OAS example responses.
type FromOASExamples struct {
	// Enabled activates getting a mock response from OAS examples or schemas documented in OAS.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Code is the default HTTP response code that the gateway reads from the path responses documented in OAS.
	Code int `bson:"code,omitempty" json:"code,omitempty"`
	// ContentType is the default HTTP response body type that the gateway reads from the path responses documented in OAS.
	ContentType string `bson:"contentType,omitempty" json:"contentType,omitempty"`
	// ExampleName is the default example name among multiple path response examples documented in OAS.
	ExampleName string `bson:"exampleName,omitempty" json:"exampleName,omitempty"`
}

func (*MockResponse) shouldImport(operation *openapi3.Operation) bool {
	for _, response := range operation.Responses {
		for _, content := range response.Value.Content {
			if content.Example != nil || content.Schema != nil {
				return true
			}

			for _, example := range content.Examples {
				if example.Value != nil {
					return true
				}
			}
		}
	}

	return false
}

// Import populates *MockResponse with enabled argument for FromOASExamples.
func (m *MockResponse) Import(enabled bool) {
	m.Enabled = enabled
	m.FromOASExamples = &FromOASExamples{
		Enabled: enabled,
	}
}

func (s *OAS) fillVirtualEndpoint(endpointMetas []apidef.VirtualMeta) {
	for _, em := range endpointMetas {
		operationID := s.getOperationID(em.Path, em.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.VirtualEndpoint == nil {
			operation.VirtualEndpoint = &VirtualEndpoint{}
		}

		operation.VirtualEndpoint.Fill(em)
		if ShouldOmit(operation.VirtualEndpoint) {
			operation.VirtualEndpoint = nil
		}
	}
}

func (o *Operation) extractVirtualEndpointTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.VirtualEndpoint == nil {
		return
	}

	meta := apidef.VirtualMeta{Path: path, Method: method}
	o.VirtualEndpoint.ExtractTo(&meta)
	ep.Virtual = append(ep.Virtual, meta)
}

func (s *OAS) fillRateLimitEndpoints(endpointMetas []apidef.RateLimitMeta) {
	for _, em := range endpointMetas {
		operationID := s.getOperationID(em.Path, em.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.RateLimit == nil {
			operation.RateLimit = &RateLimitEndpoint{}
		}

		operation.RateLimit.Fill(em)
		if ShouldOmit(operation.RateLimit) {
			operation.RateLimit = nil
		}
	}
}

func (o *Operation) extractRateLimitEndpointTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.RateLimit == nil {
		return
	}

	meta := apidef.RateLimitMeta{Path: path, Method: method}
	o.RateLimit.ExtractTo(&meta)
	ep.RateLimit = append(ep.RateLimit, meta)
}

func (s *OAS) fillEndpointPostPlugins(endpointMetas []apidef.GoPluginMeta) {
	for _, em := range endpointMetas {
		operationID := s.getOperationID(em.Path, em.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.PostPlugins == nil {
			operation.PostPlugins = make(EndpointPostPlugins, 1)
		}

		operation.PostPlugins.Fill(em)
		if ShouldOmit(operation.PostPlugins) {
			operation.PostPlugins = nil
		}
	}
}

func (o *Operation) extractEndpointPostPluginTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.PostPlugins == nil {
		return
	}

	meta := apidef.GoPluginMeta{Path: path, Method: method}
	o.PostPlugins.ExtractTo(&meta)
	ep.GoPlugin = append(ep.GoPlugin, meta)
}

func (o *Operation) extractCircuitBreakerTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.CircuitBreaker == nil {
		return
	}

	meta := apidef.CircuitBreakerMeta{Path: path, Method: method}
	o.CircuitBreaker.ExtractTo(&meta)
	ep.CircuitBreaker = append(ep.CircuitBreaker, meta)
}

func (s *OAS) fillCircuitBreaker(metas []apidef.CircuitBreakerMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.CircuitBreaker == nil {
			operation.CircuitBreaker = &CircuitBreaker{}
		}

		operation.CircuitBreaker.Fill(meta)
		if ShouldOmit(operation.CircuitBreaker) {
			operation.CircuitBreaker = nil
		}
	}
}

// genMockResponseOperationID creates a unique operation ID by combining:
// - HTTP method (e.g. GET)
// - Path (without leading slash)
// - Status code
// Example: "GET users 200" becomes "getUsers200"
func genMockResponseOperationID(mockResponse apidef.MockResponseMeta) string {
	combined := fmt.Sprintf("%v %v %d",
		mockResponse.Method,
		strings.Trim(mockResponse.Path, "/"),
		mockResponse.Code,
	)
	return toCamelCase(combined)
}

// toCamelCase converts a space/symbol separated string to camelCase.
// Example: "get users 200" becomes "getUsers200"
func toCamelCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})

	if len(words) == 0 {
		return ""
	}

	result := strings.ToLower(words[0])
	for _, word := range words[1:] {
		if word == "" {
			continue
		}
		result += strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}

	return result
}
