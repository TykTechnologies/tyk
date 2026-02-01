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

// WriteJSONRPCError writes a JSON-RPC 2.0 formatted error response.
// The HTTP status code is mapped to an appropriate JSON-RPC error code,
// and the original HTTP code is included in the data field for debugging.
func WriteJSONRPCError(w http.ResponseWriter, requestID interface{}, httpCode int, message string) {
	rpcCode := MapHTTPStatusToJSONRPCCode(httpCode)

	response := buildErrorResponse(requestID, rpcCode, message, httpCode)

	writeJSONResponse(w, httpCode, response)
}

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

func writeJSONResponse(w http.ResponseWriter, httpCode int, response JSONRPCErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)

	// Encode response - errors are logged but not critical here
	// as the error handler is already dealing with an error condition
	_ = json.NewEncoder(w).Encode(response)
}
