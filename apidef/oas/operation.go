package oas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/TykTechnologies/tyk/regexp"
)

// Operations holds Operation definitions. The string key in this object is the `operationID`, which is a unique identifier for each API operation. 
type Operations map[string]*Operation

// Operation holds a request operation configuration, allowances, tranformations, caching, timeouts and validation.
type Operation struct {
	// Allow request by allowance.
	Allow *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`

	// Block request by allowance.
	Block *Allowance `bson:"block,omitempty" json:"block,omitempty"`

	// IgnoreAuthentication ignores authentication on request by allowance.
	// 
	// Tyk classic API definition: version_data.versions..extended_paths.ignored[].
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
		s.Paths = openapi3.NewPaths()
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
// This method only handles direct mock response conversions, as other middleware
// configurations (like allow lists, block lists, etc.) are converted to classic
// API mock responses in an earlier step of the process.
//
// For each mock response, it:
// 1. Creates an OAS operation with a unique ID (if it doesn't exist)
// 2. Sets up the mock response with content type detection and example values
// 3. Configures the operation to ignore authentication for this endpoint
//
// The content type is determined by:
// - Checking the Content-Type header if present
// - Attempting to parse the body as JSON
// - Defaulting to text/plain if neither above applies
func (s *OAS) fillMockResponsePaths(paths *openapi3.Paths, ep apidef.ExtendedPathsSet) {
	for _, mock := range ep.MockResponse {
		operationID := s.getOperationID(mock.Path, mock.Method)

		var operation *openapi3.Operation

		for _, item := range paths.Map() {
			if op := item.GetOperation(mock.Method); op != nil && op.OperationID == operationID {
				operation = op
				break
			}
		}

		if operation.Responses == nil {
			operation.Responses = openapi3.NewResponses()
		}

		// Response description is required by the OAS spec, but we don't have it in Tyk classic.
		// So we're using a dummy value to satisfy the spec.
		var oasDesc string

		response := &openapi3.Response{
			Description: &oasDesc,
		}

		operation.Responses.Set(strconv.Itoa(mock.Code), &openapi3.ResponseRef{
			Value: response,
		})

		operation.Responses.Delete("default")

		tykOperation := s.GetTykExtension().getOperation(operation.OperationID)

		if tykOperation.MockResponse == nil {
			tykOperation.MockResponse = &MockResponse{}
		}

		tykOperation.MockResponse.Fill(mock)

		if tykOperation.IgnoreAuthentication == nil && tykOperation.MockResponse.FromOASExamples == nil {
			// We need to to add ignoreAuthentication middleware to the operation
			// to stay consistent to the way mock responses work for classic APIs
			tykOperation.IgnoreAuthentication = &Allowance{Enabled: true}
		}

		if ShouldOmit(tykOperation.MockResponse) {
			tykOperation.MockResponse = &MockResponse{
				FromOASExamples: &FromOASExamples{},
			}
		}
	}
}

func (s *OAS) extractPathsAndOperations(ep *apidef.ExtendedPathsSet) {
	ep.Clear()

	tykOperations := s.getTykOperations()
	if len(tykOperations) == 0 {
		return
	}

	for _, pathItem := range oasutil.SortByPathLength(*s.Paths) {
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
					break
				}
			}
		}
	}

	sortMockResponseAllowList(ep)
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
			// Skip endpoints that have mock responses configured via method actions, we should avoid
			// creating allowance for them.
			if hasMockResponse(em.MethodActions) {
				continue
			}

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
	trimmedPath := strings.Trim(inPath, "/")

	if trimmedPath == "" {
		return []pathPart{}, false
	}

	parts := strings.Split(trimmedPath, "/")
	result := make([]pathPart, len(parts))

	regexCount := 0
	hasRegex := false

	for i, segment := range parts {
		var part pathPart
		part, regexCount, hasRegex = parsePathSegment(segment, regexCount, hasRegex)
		result[i] = part
	}

	return result, hasRegex
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
		if s.Paths.Value(item) == nil {
			s.Paths.Set(item, &openapi3.PathItem{})
		}

		return s.Paths.Value(item)
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

		// We should check if the parameters are already set before initializing it.
		if p.Parameters == nil {
			p.Parameters = []*openapi3.ParameterRef{}
		}

		existingParams := make(map[string]bool)
		for _, existingParam := range p.Parameters {
			existingParams[existingParam.Value.Name] = true
		}

		for _, part := range parts {
			// Skip adding the parameter if it already exists so that we don't override it.
			if existingParams[part.name] {
				continue
			}

			if part.isRegex {
				schema := &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type:    &openapi3.Types{openapi3.TypeString},
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
	for _, response := range operation.Responses.Map() {
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

// detectMockResponseContentType determines the Content-Type of the mock response.
// It first checks the headers for an explicit Content-Type, then attempts to detect
// the type from the body content. Returns "text/plain" if no specific type can be determined.
func detectMockResponseContentType(mock apidef.MockResponseMeta) string {
	const headerContentType = "Content-Type"

	for name, value := range mock.Headers {
		if http.CanonicalHeaderKey(name) == headerContentType {
			return value
		}
	}

	if mock.Body == "" {
		return "text/plain"
	}

	// We attempt to guess the content type by checking if the body is a valid JSON.
	var arrayValue = []json.RawMessage{}
	if err := json.Unmarshal([]byte(mock.Body), &arrayValue); err == nil {
		return "application/json"
	}

	var objectValue = map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(mock.Body), &objectValue); err == nil {
		return "application/json"
	}

	return "text/plain"
}

// sortMockResponseAllowList sorts the mock response paths by path, method, and response code.
// This ensures a deterministic order of mock responses.
func sortMockResponseAllowList(ep *apidef.ExtendedPathsSet) {
	sort.Slice(ep.WhiteList, func(i, j int) bool {
		// First sort by path
		if ep.WhiteList[i].Path != ep.WhiteList[j].Path {
			return ep.WhiteList[i].Path < ep.WhiteList[j].Path
		}
		// Then by method
		if ep.WhiteList[i].Method != ep.WhiteList[j].Method {
			return ep.WhiteList[i].Method < ep.WhiteList[j].Method
		}

		// Finally by response code
		actionI, existsI := ep.WhiteList[i].MethodActions[ep.WhiteList[i].Method]
		actionJ, existsJ := ep.WhiteList[j].MethodActions[ep.WhiteList[j].Method]

		// If either method action doesn't exist, maintain stable sort order
		if !existsI || !existsJ {
			return false
		}

		return actionI.Code < actionJ.Code
	})
}

// hasMockResponse returns true if any method action has a Reply action type.
// This is used to determine if an endpoint should be treated as a mock response.
func hasMockResponse(methodActions map[string]apidef.EndpointMethodMeta) bool {
	for _, action := range methodActions {
		if action.Action == apidef.Reply {
			return true
		}
	}

	return false
}

// parsePathSegment parses a single path segment and determines if it contains a regex pattern.
func parsePathSegment(segment string, regexCount int, hasRegex bool) (pathPart, int, bool) {
	if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
		return parseMuxTemplate(segment, regexCount)
	} else if isIdentifier(segment) {
		return pathPart{name: segment, value: segment, isRegex: false}, regexCount, hasRegex
	} else {
		regexCount++
		return pathPart{name: fmt.Sprintf("customRegex%d", regexCount), value: segment, isRegex: true}, regexCount, true
	}
}

// parseMuxTemplate parses a segment that is a mux template and extracts the name or assigns a custom regex name.
func parseMuxTemplate(segment string, regexCount int) (pathPart, int, bool) {
	segment = strings.Trim(segment, "{}")

	name, _, ok := strings.Cut(segment, ":")
	if ok || isIdentifier(segment) {
		return pathPart{name: name, isRegex: true}, regexCount, true
	}

	regexCount++
	return pathPart{name: fmt.Sprintf("customRegex%d", regexCount), isRegex: true}, regexCount, true
}

func isIdentifier(value string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, value) //nolint
	return matched
}
