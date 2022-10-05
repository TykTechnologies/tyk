package oas

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

type Operations map[string]*Operation

type Operation struct {
	Allow                *Allowance `bson:"allow,omitempty" json:"allow,omitempty"`
	Block                *Allowance `bson:"block,omitempty" json:"block,omitempty"`
	IgnoreAuthentication *Allowance `bson:"ignoreAuthentication,omitempty" json:"ignoreAuthentication,omitempty"`
	// TransformRequestMethod allows you to transform the method of a request.
	TransformRequestMethod *TransformRequestMethod `bson:"transformRequestMethod,omitempty" json:"transformRequestMethod,omitempty"`
	// TransformRequestBody allows you to transform request body.
	// When both `path` and `body` are provided, body would take precedence.
	TransformRequestBody *TransformRequestBody `bson:"transformRequestBody,omitempty" json:"transformRequestBody,omitempty"`
	Cache                *CachePlugin          `bson:"cache,omitempty" json:"cache,omitempty"`
	EnforceTimeout       *EnforceTimeout       `bson:"enforceTimeout,omitempty" json:"enforceTimeout,omitempty"`
	ValidateRequest      *ValidateRequest      `bson:"validateRequest,omitempty" json:"validateRequest,omitempty"`
	MockResponse         *MockResponse         `bson:"mockResponse,omitempty" json:"mockResponse,omitempty"`
}

const (
	allow                AllowanceType = 0
	block                AllowanceType = 1
	ignoreAuthentication AllowanceType = 2
	contentTypeJSON                    = "application/json"
)

func (o *Operation) Import(oasOperation *openapi3.Operation, allowList, validateRequest *bool) {
	if allowList != nil {
		allow := o.Allow
		if allow == nil {
			allow = &Allowance{}
		}

		allow.Import(*allowList)

		if block := o.Block; block != nil && block.Enabled && *allowList {
			block.Enabled = false
		}

		o.Allow = allow
	}

	if validateRequest != nil {
		validate := o.ValidateRequest
		if validate == nil {
			validate = &ValidateRequest{}
		}

		if shouldImport := validate.shouldImportValidateRequest(oasOperation); !shouldImport {
			return
		}

		validate.Import(*validateRequest)
		o.ValidateRequest = validate
	}
}

type AllowanceType int

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
	s.fillCache(ep.AdvanceCacheConfig)
	s.fillEnforceTimeout(ep.HardTimeouts)
	s.fillOASValidateRequest(ep.ValidateRequest)
}

func (s *OAS) extractPathsAndOperations(ep *apidef.ExtendedPathsSet) {
	tykOperations := s.getTykOperations()
	if len(tykOperations) == 0 {
		return
	}

	for id, tykOp := range tykOperations {
	found:
		for path, pathItem := range s.Paths {
			for method, operation := range pathItem.Operations() {
				if id == operation.OperationID {
					tykOp.extractAllowanceTo(ep, path, method, allow)
					tykOp.extractAllowanceTo(ep, path, method, block)
					tykOp.extractAllowanceTo(ep, path, method, ignoreAuthentication)
					tykOp.extractTransformRequestMethodTo(ep, path, method)
					tykOp.extractTransformRequestBodyTo(ep, path, method)
					tykOp.extractCacheTo(ep, path, method)
					tykOp.extractEnforceTimeoutTo(ep, path, method)
					tykOp.extractOASValidateRequestTo(ep, path, method)
					break found
				}
			}
		}
	}
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
			operation.TransformRequestBody = &TransformRequestBody{}
		}

		operation.TransformRequestBody.Fill(meta)
		if ShouldOmit(operation.TransformRequestBody) {
			operation.TransformRequestBody = nil
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

func (o *Operation) extractOASValidateRequestTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.ValidateRequest == nil {
		return
	}

	meta := apidef.ValidateRequestMeta{Path: path, Method: method}
	o.ValidateRequest.ExtractTo(&meta)
	ep.ValidateRequest = append(ep.ValidateRequest, meta)
}

// detect possible regex pattern:
// - character match ([a-z])
// - greedy match (*)
// - ungreedy match (+)
// - any char (.)
// - end of string ($)
const regexPatterns = "[].+*$"

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

// splitPath splits url into folder parts, detecting regex patterns
func splitPath(inPath string) ([]pathPart, bool) {
	// Each url fragment can contain a regex, but the whole
	// url isn't just a regex (`/a/.*/foot` => `/a/{param1}/foot`)
	parts := strings.Split(strings.Trim(inPath, "/"), "/")
	result := make([]pathPart, len(parts))
	found := 0

	for k, value := range parts {
		name := value
		isRegex := strings.ContainsAny(value, regexPatterns)
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

// buildPath converts the url paths with regex to named parameters
// e.g. ["a", ".*"] becomes /a/{customRegex1}
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
			operation = &openapi3.Operation{}
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

type ValidateRequest struct {
	Enabled           bool `bson:"enabled" json:"enabled"`
	ErrorResponseCode int  `bson:"errorResponseCode,omitempty" json:"errorResponseCode,omitempty"`
}

func (v *ValidateRequest) Fill(meta apidef.ValidateRequestMeta) {
	v.Enabled = meta.Enabled
	v.ErrorResponseCode = meta.ErrorResponseCode
}

func (v *ValidateRequest) ExtractTo(meta *apidef.ValidateRequestMeta) {
	meta.Enabled = v.Enabled
	meta.ErrorResponseCode = v.ErrorResponseCode
}

func (v *ValidateRequest) shouldImportValidateRequest(operation *openapi3.Operation) bool {
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

func (v *ValidateRequest) Import(enabled bool) {
	v.Enabled = enabled
	v.ErrorResponseCode = http.StatusUnprocessableEntity
}

func (s *OAS) fillOASValidateRequest(metas []apidef.ValidateRequestMeta) {
	for _, meta := range metas {
		operationID := s.getOperationID(meta.Path, meta.Method)
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

type MockResponse struct {
	Enabled         bool              `bson:"enabled" json:"enabled"`
	Code            int               `bson:"code,omitempty" json:"code,omitempty"`
	Body            string            `bson:"body,omitempty" json:"body,omitempty"`
	Headers         map[string]string `bson:"headers,omitempty" json:"headers,omitempty"`
	FromOASExamples *FromOASExamples  `bson:"fromOASExamples,omitempty" json:"fromOASExamples,omitempty"`
}

type FromOASExamples struct {
	// Enabled enables getting a mock response from OAS examples or schemas documented in OAS.
	Enabled bool `bson:"enabled" json:"enabled"`
	// Code is the default HTTP response code that the gateway reads from the path responses documented in OAS.
	Code int `bson:"code,omitempty" json:"code,omitempty"`
	// ContentType is the default HTTP response body type that the gateway reads from the path responses documented in OAS.
	ContentType string `bson:"contentType,omitempty" json:"contentType,omitempty"`
	// ExampleName is the default example name among multiple path response examples documented in OAS.
	ExampleName string `bson:"exampleName,omitempty" json:"exampleName,omitempty"`
}
