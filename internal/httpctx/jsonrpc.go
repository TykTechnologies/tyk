package httpctx

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

// JSONRPCRequestData holds parsed JSON-RPC request information for MCP routing.
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
