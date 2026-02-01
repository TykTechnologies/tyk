package errors

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

// JSONRPCError represents a JSON-RPC 2.0 error object as defined in the specification.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSONRPCErrorResponse represents a complete JSON-RPC 2.0 error response.
type JSONRPCErrorResponse struct {
	JSONRPC string       `json:"jsonrpc"`
	Error   JSONRPCError `json:"error"`
	ID      interface{}  `json:"id"`
}

// WriteJSONRPCError writes a JSON-RPC 2.0 error response to the HTTP response writer.
// It maps the HTTP status code to an appropriate JSON-RPC error code and formats
// the response according to the JSON-RPC 2.0 specification.
//
// Parameters:
//   - w: HTTP response writer
//   - requestID: The JSON-RPC request ID (can be string, number, or null)
//   - httpCode: HTTP status code to be mapped to JSON-RPC error code
//   - message: Error message describing what went wrong
//
// The response will include the original HTTP status code in the error data field
// for debugging purposes.
func WriteJSONRPCError(w http.ResponseWriter, requestID interface{}, httpCode int, message string) {
	rpcCode := MapHTTPStatusToJSONRPCCode(httpCode)

	response := buildErrorResponse(requestID, rpcCode, message, httpCode)

	writeJSONResponse(w, httpCode, response)
}

// buildErrorResponse constructs a JSON-RPC error response structure.
func buildErrorResponse(requestID interface{}, rpcCode int, message string, httpCode int) JSONRPCErrorResponse {
	return JSONRPCErrorResponse{
		JSONRPC: apidef.JsonRPC20,
		Error: JSONRPCError{
			Code:    rpcCode,
			Message: message,
			Data: map[string]interface{}{
				"http_code": httpCode,
			},
		},
		ID: requestID,
	}
}

// writeJSONResponse writes the JSON-RPC response with appropriate headers.
func writeJSONResponse(w http.ResponseWriter, httpCode int, response JSONRPCErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)

	// Encode response - errors are logged but not critical here
	// as the error handler is already dealing with an error condition
	_ = json.NewEncoder(w).Encode(response)
}
