package httpctx

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

// JSONRPCRequestData holds parsed JSON-RPC request information for protocol routing (MCP, A2A, etc.).
type JSONRPCRequestData struct {
	// Method is the JSON-RPC method name (e.g., "tools/call", "resources/read").
	Method string
	// Params contains the raw JSON parameters from the request.
	Params json.RawMessage
	// ID is the JSON-RPC request ID (can be string, number, or null).
	ID interface{}
	// VEMPath is the internal VEM path used for routing.
	VEMPath string
	// Primitive is the name of the tool/resource/prompt being accessed.
	Primitive string
}

var jsonrpcRequestValue = NewValue[*JSONRPCRequestData](ctx.JSONRPCRequest)

// SetJSONRPCRequest stores parsed JSON-RPC request data in the request context.
func SetJSONRPCRequest(r *http.Request, data *JSONRPCRequestData) {
	jsonrpcRequestValue.Set(r, data)
}

// GetJSONRPCRequest retrieves parsed JSON-RPC request data from the request context.
// Returns nil if no JSON-RPC data has been stored.
func GetJSONRPCRequest(r *http.Request) *JSONRPCRequestData {
	return jsonrpcRequestValue.Get(r)
}

var jsonrpcRoutingValue = NewValue[bool](ctx.JsonRPCRouting)

// SetJsonRPCRouting sets the JSON-RPC routing flag in the request context.
// This is used by JSON-RPC routers (MCP, A2A, etc.) to indicate that a request
// is being routed internally to a protocol-specific endpoint.
func SetJsonRPCRouting(r *http.Request, enabled bool) {
	jsonrpcRoutingValue.Set(r, enabled)
}

// IsJsonRPCRouting returns true if the request came via JSON-RPC routing.
// This is checked by the access control logic to allow internal endpoint access.
func IsJsonRPCRouting(r *http.Request) bool {
	return jsonrpcRoutingValue.Get(r)
}
