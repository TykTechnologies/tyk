package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/user"
)

// skipAuthIfMarked returns (true, session) when the request is marked
// for auth-skip via httpctx.SetSkipAuth AND a synthetic session is
// already present in context. Auth middlewares MUST invoke this as
// the FIRST statement of ProcessRequest and early-return on (true, _).
//
// The boolean alone is the skip signal. Returning the session is a
// courtesy for sites that want to surface it for logging.
//
// See RFC §10.2 (option c) and the helper-placement contract: the call
// MUST precede any closure construction, IDP calls, secret-getter
// callbacks, r.Clone, span starts, cache lookups, header reads, or any
// other side-effecting work.
func skipAuthIfMarked(r *http.Request) (bool, *user.SessionState) {
	if !httpctx.IsAuthSkipped(r) {
		return false, nil
	}
	sess := ctxGetSession(r)
	return true, sess
}
