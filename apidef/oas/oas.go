package oas

import (
	"encoding/json"
	"sort"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
)

const ExtensionTykAPIGateway = "x-tyk-api-gateway"

type OAS struct {
	openapi3.T
}

func (s *OAS) Fill(api apidef.APIDefinition) {
	s.fillPathsAndOperations(api.VersionData.Versions[""].ExtendedPaths)
	s.GetTykExtension().Fill(api)
}

func (s *OAS) ExtractTo(api *apidef.APIDefinition) {
	var ep apidef.ExtendedPathsSet
	s.GetTykExtension().ExtractTo(api)
	s.extractPathsAndOperations(&ep)
	s.extractSecuritySchemes(api, true)
	v := api.VersionData.Versions[""]
	v.UseExtendedPaths = true
	v.ExtendedPaths = ep
	api.VersionData.Versions[""] = v
}

func (s *OAS) GetTykExtension() *XTykAPIGateway {
	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
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

	newVal := &XTykAPIGateway{}
	s.Extensions[ExtensionTykAPIGateway] = newVal

	return newVal
}

func (s *OAS) getOperationID(path, method string) (operationID string) {
	operationID = path + method + "Operation"

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

func (s *OAS) fillPathsAndOperations(ep apidef.ExtendedPathsSet) {
	if s.Paths == nil {
		s.Paths = make(openapi3.Paths)
	}

	if s.Extensions == nil {
		s.Extensions = make(map[string]interface{})
	}

	s.fillAllowance(ep.WhiteList, allow)
	s.fillAllowance(ep.BlackList, block)
	s.fillAllowance(ep.Ignored, ignoreAuthentication)
	s.fillMockResponse(ep.MockResponse)
}

func (s *OAS) fillAllowance(endpointMetas []apidef.EndPointMeta, typ AllowanceType) {
	for _, em := range endpointMetas {
		operationID := s.getOperationID(em.Path, em.Method)
		operation := s.GetTykExtension().getOperation(operationID)

		var allowance *Allowance

		switch typ {
		case block:
			if operation.Block == nil {
				operation.Block = &Allowance{}
			}

			allowance = operation.Block
		case ignoreAuthentication:
			if operation.IgnoreAuthentication == nil {
				operation.IgnoreAuthentication = &Allowance{}
			}

			allowance = operation.IgnoreAuthentication
		default:
			if operation.Allow == nil {
				operation.Allow = &Allowance{}
			}

			allowance = operation.Allow
		}

		allowance.Fill(em)
		if ShouldOmit(allowance) {
			allowance = nil
		}
	}
}

func (s *OAS) fillMockResponse(mockMetas []apidef.MockResponseMeta) {
	for _, mm := range mockMetas {
		operationID := s.getOperationID(mm.Path, mm.Method)
		operation := s.GetTykExtension().getOperation(operationID)
		if operation.MockResponse == nil {
			operation.MockResponse = &MockResponse{}
		}

		operation.MockResponse.Fill(mm)
		if ShouldOmit(operation.MockResponse) {
			operation.MockResponse = nil
		}
	}
}

func (s *OAS) extractPathsAndOperations(ep *apidef.ExtendedPathsSet) {
	var paths []string
	for k := range s.Paths {
		paths = append(paths, k)
	}

	sort.Strings(paths)

	for _, path := range paths {
		for method, op := range s.Paths[path].Operations() {
			s.GetTykExtension().getOperation(op.OperationID).ExtractTo(ep, path, method)
		}
	}
}

func (s *OAS) ImportOAS() {
	if !ShouldOmit(s.Extensions[ExtensionTykAPIGateway]) {
		return
	}

	for path, val := range s.Paths {
		for method, op := range val.Operations() {
			em := apidef.EndPointMeta{
				Disabled: false,
				Path:     path,
				Method:   method,
			}

			s.GetTykExtension().getOperation(op.OperationID).Allow.Fill(em)
		}
	}
}
