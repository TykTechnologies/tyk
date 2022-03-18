package oas

import (
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
	Cache                  *CachePlugin            `bson:"cache,omitempty" json:"cache,omitempty"`
}

const (
	allow                AllowanceType = 0
	block                AllowanceType = 1
	ignoreAuthentication AllowanceType = 2
)

type AllowanceType int

func (s *OAS) fillPathsAndOperations(ep apidef.ExtendedPathsSet) {
	if s.Paths == nil {
		s.Paths = make(openapi3.Paths)
	}

	s.fillAllowance(ep.WhiteList, allow)
	s.fillAllowance(ep.BlackList, block)
	s.fillAllowance(ep.Ignored, ignoreAuthentication)
	s.fillTransformRequestMethod(ep.MethodTransforms)
	s.fillCache(ep.AdvanceCacheConfig)

	if len(s.Paths) == 0 {
		s.Paths = nil
	}
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
					tykOp.extractCacheTo(ep, path, method)
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

func (s *OAS) getOperationID(path, method string) (operationID string) {
	operationID = strings.TrimPrefix(path, "/") + method

	if s.Paths[path] == nil {
		s.Paths[path] = &openapi3.PathItem{}
	}

	p := s.Paths[path]
	operation := p.GetOperation(method)
	if operation == nil {
		p.SetOperation(method, &openapi3.Operation{OperationID: operationID})
		return operationID
	}

	if operation.OperationID == "" {
		operation.OperationID = operationID
	} else {
		operationID = operation.OperationID
	}

	return
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
