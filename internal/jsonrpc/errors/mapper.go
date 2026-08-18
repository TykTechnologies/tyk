package errors

import (
	"net/http"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
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
	// CodeQuotaExceeded indicates API quota has been exceeded (-32003).
	CodeQuotaExceeded = -32003
	// CodeRateLimitExceeded indicates rate limit has been exceeded (-32004).
	CodeRateLimitExceeded = -32004
	// CodeIPBlocked indicates the IP address is blocked (-32005).
	CodeIPBlocked = -32005
	// CodeUpstreamError indicates an upstream/backend service error (-32006).
	CodeUpstreamError = -32006

	// Modern server-defined namespace. The semantic suffix matches the legacy
	// namespace so dashboards and logs can classify both eras identically.
	CodeModernServerError       = -33000
	CodeModernAuthRequired      = -33001
	CodeModernAccessDenied      = -33002
	CodeModernQuotaExceeded     = -33003
	CodeModernRateLimitExceeded = -33004
	CodeModernIPBlocked         = -33005
	CodeModernUpstreamError     = -33006
)

type errorKind int

const (
	errorKindNone errorKind = iota
	errorKindServer
	errorKindAuth
	errorKindAccess
	errorKindRateLimit
	errorKindUpstream
	errorKindQuota
	errorKindIPBlocked
)

// SelectJSONRPCCode selects one final wire/telemetry code from the normalized
// protocol context and structured Gateway error classification.
func SelectJSONRPCCode(httpStatus int, classification *tykerrors.ErrorClassification, protocolContext *mcp.ProtocolContext) int {
	kind := classifyError(httpStatus, classification)
	if kind == errorKindNone {
		code := MapHTTPStatusToJSONRPCCode(httpStatus)
		if protocolContext.IsModern() && code >= CodeUpstreamError && code <= CodeServerError {
			return code - 1000
		}
		return code
	}
	return codeForKind(kind, protocolContext.IsModern())
}

func classifyError(httpStatus int, classification *tykerrors.ErrorClassification) errorKind {
	if classification != nil {
		switch classification.Flag {
		case tykerrors.RLT:
			return errorKindRateLimit
		case tykerrors.QEX:
			return errorKindQuota
		case tykerrors.ACD:
			return errorKindAccess
		case tykerrors.IPB:
			return errorKindIPBlocked
		case tykerrors.AMF, tykerrors.AKI, tykerrors.TKE, tykerrors.TKI, tykerrors.TCV,
			tykerrors.EAD, tykerrors.CRQ, tykerrors.CMM:
			return errorKindAuth
		case tykerrors.TLE, tykerrors.TLI, tykerrors.TLM, tykerrors.TLN, tykerrors.TLH,
			tykerrors.TLP, tykerrors.TLA, tykerrors.TLC, tykerrors.UCF, tykerrors.UCT,
			tykerrors.URR, tykerrors.URT, tykerrors.EPI, tykerrors.CAB, tykerrors.NRS,
			tykerrors.DNS, tykerrors.NRH, tykerrors.NHU, tykerrors.CBO, tykerrors.URS,
			tykerrors.UPE:
			return errorKindUpstream
		}
	}

	switch httpStatus {
	case http.StatusUnauthorized:
		return errorKindAuth
	case http.StatusForbidden:
		return errorKindAccess
	case http.StatusTooManyRequests:
		return errorKindRateLimit
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return errorKindUpstream
	default:
		return errorKindNone
	}
}

func codeForKind(kind errorKind, modern bool) int {
	legacy := map[errorKind]int{
		errorKindServer:    CodeServerError,
		errorKindAuth:      CodeAuthRequired,
		errorKindAccess:    CodeAccessDenied,
		errorKindRateLimit: CodeRateLimitExceeded,
		errorKindUpstream:  CodeUpstreamError,
		errorKindQuota:     CodeQuotaExceeded,
		errorKindIPBlocked: CodeIPBlocked,
	}[kind]
	if modern {
		return legacy - 1000
	}
	return legacy
}

// MapHTTPStatusToJSONRPCCode maps HTTP status codes to JSON-RPC error codes.
// Uses standard JSON-RPC codes (-32700 to -32603) where appropriate, and
// custom server codes (-32000 to -32099) for HTTP-specific errors like
// auth failures, rate limits, and upstream issues.
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
