package jsonrpc

import "encoding/json"

type Router interface {
	RouteMethod(method string, params json.RawMessage, primitives map[string]string) (RouteResult, error)
}

type RouteResult struct {
	VEMChain      []string
	PrimitiveName string
}
