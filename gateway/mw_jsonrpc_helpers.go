package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
)

// writeJSONRPCAccessDenied writes a JSON-RPC 2.0 error response for access-denied cases.
// Delegates to jsonrpcerrors.WriteJSONRPCError for consistent response shape and HTTP→JSON-RPC
// error code mapping across all error paths in the gateway.
func writeJSONRPCAccessDenied(w http.ResponseWriter, r *http.Request, detail string) {
	var requestID interface{}
	if state := httpctx.GetJSONRPCRoutingState(r); state != nil {
		requestID = state.ID
	}
	jsonrpcerrors.WriteJSONRPCError(w, requestID, http.StatusForbidden, detail)
}
