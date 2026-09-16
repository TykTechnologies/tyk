package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
)

// writeJSONRPCAccessDenied writes a JSON-RPC 2.0 error response for access-denied cases.
// Delegates to jsonrpcerrors.WriteJSONRPCError for consistent response shape and HTTP→JSON-RPC
// error code mapping across all error paths in the gateway.
func writeJSONRPCAccessDenied(w http.ResponseWriter, r *http.Request, detail string) {
	ctx.SetErrorClassification(r, tykerrors.NewErrorClassification(tykerrors.ACD, "access_denied").WithSource("MCPAccessControl"))
	writeMCPJSONRPCError(w, r, http.StatusForbidden, detail)
}

// writeMCPJSONRPCError selects the request's final code once, stores it for
// logs/metrics/analytics, and uses that exact code on the wire.
func writeMCPJSONRPCError(w http.ResponseWriter, r *http.Request, httpCode int, detail string) []byte {
	var requestID interface{}
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil {
		requestID = state.ID
	} else if protocolContext := httpctx.GetMCPProtocolContext(r); protocolContext != nil && protocolContext.Envelope != nil {
		requestID = protocolContext.Envelope.ID
	}
	code := jsonrpcerrors.SelectJSONRPCCode(httpCode, ctx.GetErrorClassification(r), httpctx.GetMCPProtocolContext(r))
	ctxSetJSONRPCErrorCode(r, code)
	return jsonrpcerrors.WriteJSONRPCErrorWithCode(w, requestID, httpCode, code, detail)
}
