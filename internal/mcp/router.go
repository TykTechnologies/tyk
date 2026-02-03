package mcp

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/TykTechnologies/tyk/internal/jsonrpc"
)

type Router struct {
}

func NewRouter() jsonrpc.Router {
	return &Router{}
}

func (r *Router) RouteMethod(method string, params json.RawMessage, primitives map[string]string) (jsonrpc.RouteResult, error) {
	switch method {
	case MethodToolsCall:
		return r.routeToolsCall(params, primitives)
	case MethodResourcesRead:
		return r.routeResourcesRead(params, primitives)
	case MethodPromptsGet:
		return r.routePromptsGet(params, primitives)
	default:
		return r.routeOperation(method, primitives)
	}
}

func (r *Router) routeToolsCall(params json.RawMessage, primitives map[string]string) (jsonrpc.RouteResult, error) {
	name, err := extractStringParam(params, ParamKeyName)
	if err != nil {
		return jsonrpc.RouteResult{}, err
	}

	operationVEM, found := primitives[PrimitiveKeyOperation+MethodToolsCall]
	if !found {
		operationVEM = jsonrpc.MethodVEMPrefix + MethodToolsCall
	}

	toolVEM, found := primitives[PrimitiveKeyTool+name]
	if !found {
		toolVEM = ToolPrefix + name
	}

	return jsonrpc.RouteResult{
		VEMChain:      []string{operationVEM, toolVEM},
		PrimitiveName: name,
	}, nil
}

func (r *Router) routeResourcesRead(params json.RawMessage, primitives map[string]string) (jsonrpc.RouteResult, error) {
	uri, err := extractStringParam(params, ParamKeyURI)
	if err != nil {
		return jsonrpc.RouteResult{}, err
	}

	operationVEM, found := primitives[PrimitiveKeyOperation+MethodResourcesRead]
	if !found {
		operationVEM = jsonrpc.MethodVEMPrefix + MethodResourcesRead
	}

	resourceVEM, found := matchResourceURI(uri, primitives)
	if !found {
		resourceVEM = ResourcePrefix + uri
	}

	return jsonrpc.RouteResult{
		VEMChain:      []string{operationVEM, resourceVEM},
		PrimitiveName: uri,
	}, nil
}

func (r *Router) routePromptsGet(params json.RawMessage, primitives map[string]string) (jsonrpc.RouteResult, error) {
	name, err := extractStringParam(params, ParamKeyName)
	if err != nil {
		return jsonrpc.RouteResult{}, err
	}

	operationVEM, found := primitives[PrimitiveKeyOperation+MethodPromptsGet]
	if !found {
		operationVEM = jsonrpc.MethodVEMPrefix + MethodPromptsGet
	}

	promptVEM, found := primitives[PrimitiveKeyPrompt+name]
	if !found {
		promptVEM = PromptPrefix + name
	}

	return jsonrpc.RouteResult{
		VEMChain:      []string{operationVEM, promptVEM},
		PrimitiveName: name,
	}, nil
}

func (r *Router) routeOperation(method string, primitives map[string]string) (jsonrpc.RouteResult, error) {
	operationVEM, found := primitives[PrimitiveKeyOperation+method]
	if !found {
		operationVEM = jsonrpc.MethodVEMPrefix + method
	}

	return jsonrpc.RouteResult{
		VEMChain:      []string{operationVEM},
		PrimitiveName: method,
	}, nil
}

func extractStringParam(params json.RawMessage, key string) (string, error) {
	if len(params) == 0 {
		return "", errors.New(ErrMsgMissingParams)
	}

	var paramsMap map[string]interface{}
	if json.Unmarshal(params, &paramsMap) != nil {
		return "", errors.New(ErrMsgInvalidParamsType)
	}

	val, exists := paramsMap[key]
	if !exists {
		switch key {
		case ParamKeyName:
			return "", errors.New(ErrMsgMissingParamName)
		case ParamKeyURI:
			return "", errors.New(ErrMsgMissingParamURI)
		default:
			return "", errors.New(ErrMsgInvalidParams)
		}
	}

	strVal, ok := val.(string)
	if !ok || strVal == "" {
		return "", errors.New(ErrMsgInvalidParams)
	}

	return strVal, nil
}

func matchResourceURI(uri string, primitives map[string]string) (string, bool) {
	if vem, ok := primitives[PrimitiveKeyResource+uri]; ok {
		return vem, true
	}

	var bestMatch string
	var bestVEM string
	bestLen := -1

	for key, vem := range primitives {
		if !strings.HasPrefix(key, PrimitiveKeyResource) {
			continue
		}

		pattern := strings.TrimPrefix(key, PrimitiveKeyResource)
		if !strings.HasSuffix(pattern, "/*") {
			continue
		}

		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(uri, prefix) {
			prefixLen := len(prefix)
			if prefixLen > bestLen || (prefixLen == bestLen && pattern < bestMatch) {
				bestMatch = pattern
				bestVEM = vem
				bestLen = prefixLen
			}
		}
	}

	if bestLen >= 0 {
		return bestVEM, true
	}

	return "", false
}
