package jsonrpc

import "encoding/json"

// SW-REQ-025
type Router interface {
	RouteMethod(method string, params json.RawMessage, primitives map[string]string) (RouteResult, error)
}

// SW-REQ-025
type RouteResult struct {
	VEMChain      []string
	PrimitiveName string
}
