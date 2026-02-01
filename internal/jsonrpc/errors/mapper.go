package errors

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/mcp"
)

// Custom JSON-RPC error codes in the server-defined range (-32000 to -32099).
// These codes are used to map HTTP error statuses to JSON-RPC error responses
// while preserving semantic meaning.
const (
	// CodeServerError is a generic server error (-32000).
	CodeServerError = -32000
	// CodeAuthRequired indicates authentication is required (-32001).
	CodeAuthRequired = -32001
	// CodeAccessDenied indicates authorization failed (-32002).
	CodeAccessDenied = -32002
	// CodeRateLimitExceeded indicates rate limit has been exceeded (-32003).
	CodeRateLimitExceeded = -32003
	// CodeUpstreamError indicates an upstream/backend service error (-32004).
	CodeUpstreamError = -32004
	// CodeQuotaExceeded indicates API quota has been exceeded (-32005).
	CodeQuotaExceeded = -32005
	// CodeIPBlocked indicates the IP address is blocked (-32006).
	CodeIPBlocked = -32006
)

// MapHTTPStatusToJSONRPCCode maps HTTP status codes to JSON-RPC 2.0 error codes.
// It follows the JSON-RPC 2.0 specification for standard error codes and uses
// the server-defined range (-32000 to -32099) for HTTP-specific errors.
//
// Standard JSON-RPC codes (predefined):
//
//	-32700: Parse error
//	-32600: Invalid Request
//	-32601: Method not found
//	-32602: Invalid params
//	-32603: Internal error
//
// Custom codes (server-defined -32000 to -32099):
//
//	-32000: Generic server error
//	-32001: Authentication required (401)
//	-32002: Access denied (403)
//	-32003: Rate limit exceeded (429)
//	-32004: Upstream error (502, 503, 504)
//	-32005: Quota exceeded
//	-32006: IP blocked
//
// Returns 0 for success status codes (2xx, 3xx).
func MapHTTPStatusToJSONRPCCode(httpStatus int) int {
	// Success statuses don't need JSON-RPC error codes
	if httpStatus < 400 {
		return 0
	}

	switch httpStatus {
	case http.StatusBadRequest:
		return mcp.JSONRPCInvalidRequest

	case http.StatusUnauthorized:
		return CodeAuthRequired

	case http.StatusForbidden:
		return CodeAccessDenied

	case http.StatusNotFound:
		return mcp.JSONRPCMethodNotFound

	case http.StatusMethodNotAllowed:
		return mcp.JSONRPCInvalidRequest

	case http.StatusTooManyRequests:
		return CodeRateLimitExceeded

	case http.StatusInternalServerError:
		return mcp.JSONRPCInternalError

	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return CodeUpstreamError

	default:
		// Map other 5xx errors to internal error
		if httpStatus >= 500 {
			return mcp.JSONRPCInternalError
		}
		// Map other 4xx errors to generic server error
		return CodeServerError
	}
}
