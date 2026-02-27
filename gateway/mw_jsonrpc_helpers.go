package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	jsonrpcerrors "github.com/TykTechnologies/tyk/internal/jsonrpc/errors"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/user"
)

// checkAccessControlRules evaluates allow/block lists against a name.
// Returns true if the name is denied, false if permitted.
//
// Evaluation order:
//  1. Blocked is checked first — if matched, the request is denied.
//  2. If Allowed is non-empty and the name does not match any entry, the request is denied.
//  3. If both lists are empty, access is permitted.
func checkAccessControlRules(rules user.AccessControlRules, name string) bool {
	for _, pattern := range rules.Blocked {
		if matchPattern(pattern, name) {
			return true
		}
	}

	if len(rules.Allowed) == 0 {
		return false
	}

	for _, pattern := range rules.Allowed {
		if matchPattern(pattern, name) {
			return false
		}
	}

	return true
}

// matchPattern tests name against a regex pattern anchored with ^...$, enforcing full-match semantics.
// Uses the tyk/regexp package which caches compiled patterns.
// Falls back to exact-string comparison if the pattern is not valid regex.
func matchPattern(pattern, name string) bool {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return pattern == name
	}
	return re.MatchString(name)
}

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
