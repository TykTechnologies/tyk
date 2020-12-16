package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/getkin/kin-openapi/openapi3"
	"strconv"
	"strings"
)

type TransformHeadersConverter struct {}

func (c TransformHeadersConverter) AppendToSwagger(swaggerPaths openapi3.Paths, tykTReqHeaders []apidef.HeaderInjectionMeta, tykTResHeaders []apidef.HeaderInjectionMeta) {
	if swaggerPaths == nil {
		swaggerPaths = make(openapi3.Paths)
	}

	for _, tykTReqHeader := range tykTReqHeaders {
		plugins := PluginsForPathAndMethod(swaggerPaths,tykTReqHeader.Path, tykTReqHeader.Method)
		if plugins.TransformHeaders == nil {
			plugins.TransformHeaders = &TransformHeaders{}
		}
		plugins.TransformHeaders.Request = &TransformHeader{
			Add:    tykTReqHeader.AddHeaders,
			Delete: tykTReqHeader.DeleteHeaders,
		}
	}

	for _, tykTResHeader := range tykTResHeaders {
		plugins := PluginsForPathAndMethod(swaggerPaths,tykTResHeader.Path, tykTResHeader.Method)
		if plugins.TransformHeaders == nil {
			plugins.TransformHeaders = &TransformHeaders{}
		}

		plugins.TransformHeaders.Response = &TransformHeader{
			Add:    tykTResHeader.AddHeaders,
			Delete: tykTResHeader.DeleteHeaders,
		}
	}
}

func (c TransformHeadersConverter) AppendToTyk(tykTReqHeaders []apidef.HeaderInjectionMeta, tykTResHeaders []apidef.HeaderInjectionMeta, path, method string, swaggerTH *TransformHeaders) ([]apidef.HeaderInjectionMeta, []apidef.HeaderInjectionMeta) {
	if swaggerTH == nil {
		return tykTReqHeaders, tykTResHeaders
	}

	if swaggerTReqHeaders := swaggerTH.Request; swaggerTReqHeaders != nil {
		tykTReqHeaders = append(tykTReqHeaders,
			apidef.HeaderInjectionMeta{
				AddHeaders:    swaggerTReqHeaders.Add,
				DeleteHeaders: swaggerTReqHeaders.Delete,
				Path:          path,
				Method:        method,
			})
	}

	if swaggerTResHeaders := swaggerTH.Response; swaggerTResHeaders != nil {
		tykTResHeaders = append(tykTResHeaders,
			apidef.HeaderInjectionMeta{
				AddHeaders:    swaggerTResHeaders.Add,
				DeleteHeaders: swaggerTResHeaders.Delete,
				Path:          path,
				Method:        method,
			})
	}

	return tykTReqHeaders, tykTResHeaders
}

type EndpointMetasConverter struct {}

func (c EndpointMetasConverter) AppendToSwagger(swaggerPaths openapi3.Paths, endpointMetas []apidef.EndPointMeta, typ EndpointMetaType) {
	if swaggerPaths == nil {
		swaggerPaths = make(openapi3.Paths)
	}

	for _, endpointMeta := range endpointMetas {
		for method, methodAction := range endpointMeta.MethodActions {
			plugins := PluginsForPathAndMethod(swaggerPaths,endpointMeta.Path, method)

			p := &Allow{
				IgnoreCase: endpointMeta.IgnoreCase,
			}
			switch typ {
			case whiteList:
				plugins.Allowed = p
			case blackList:
				plugins.Blocked = p
			case ignored:
				plugins.IgnoreAuthentication = p
			}

			if methodAction.Action == apidef.Reply {
				if plugins.Mock == nil {
					plugins.Mock = make(map[string]*Mock)
				}
				plugins.Mock[strconv.Itoa(methodAction.Code)] = &Mock{
					Data:    methodAction.Data,
					Headers: methodAction.Headers,
				}
			}
		}
	}
}

func (c EndpointMetasConverter) AppendToTyk(endpointMetas []apidef.EndPointMeta, path string, method string, swaggerAllow *Allow, swaggerMocks map[string]*Mock) []apidef.EndPointMeta {
	if swaggerAllow == nil {
		return endpointMetas
	}

	endPointMeta := apidef.EndPointMeta{Path: path, IgnoreCase: swaggerAllow.IgnoreCase}

	var action apidef.EndpointMethodAction
	if swaggerMocks == nil {
		action = apidef.NoAction
		swaggerMocks = map[string]*Mock{
			"200": {Headers: make(map[string]string)},
		}
	} else {
		action = apidef.Reply
	}

	for code, mockMeta := range swaggerMocks {
		codeInt, _ := strconv.Atoi(code)
		exists := false
		for _, epMeta := range endpointMetas {
			if epMeta.Path == path {
				c.appendMethodActionsToTykEndpointMeta(&epMeta, action, method, codeInt, mockMeta)
				exists = true
				break
			}
		}

		if !exists {
			c.appendMethodActionsToTykEndpointMeta(&endPointMeta, action, method, codeInt, mockMeta)
			endpointMetas = append(endpointMetas, endPointMeta)
		}
	}

	return endpointMetas
}

func (c *EndpointMetasConverter) appendMethodActionsToTykEndpointMeta(tykEndpointMeta *apidef.EndPointMeta, tykEndpointMethodAction apidef.EndpointMethodAction, method string, code int, swaggerMock *Mock) {
	if tykEndpointMeta.MethodActions == nil {
		tykEndpointMeta.MethodActions = make(map[string]apidef.EndpointMethodMeta)
	}

	tykEndpointMeta.MethodActions[strings.ToUpper(method)] = apidef.EndpointMethodMeta{
		Action:  tykEndpointMethodAction,
		Code:    code,
		Data:    swaggerMock.Data,
		Headers: swaggerMock.Headers,
	}
}

func PluginsForPathAndMethod(paths openapi3.Paths, path string, method string) *XTykPlugins {
	if _, ok := paths[path]; !ok {
		paths[path] = &openapi3.PathItem{}
	}

	pathItem := paths[path]
	if pathItem == nil {
		pathItem = &openapi3.PathItem{}
	}

	var operation *openapi3.Operation
	if operation = pathItem.GetOperation(strings.ToUpper(method)); operation == nil {
		operation = &openapi3.Operation{}
		pathItem.SetOperation(strings.ToUpper(method), operation)
	}

	if operation.Extensions == nil {
		operation.Extensions = make(map[string]interface{})
	}

	var xTykPlugins interface{}
	var ok bool

	if xTykPlugins, ok = operation.Extensions[ExtensionXTykPlugins]; !ok {
		xTykPlugins = &XTykPlugins{}
		operation.Extensions[ExtensionXTykPlugins] = xTykPlugins
	}

	return xTykPlugins.(*XTykPlugins)
}
