package gateway

import (
	"context"
	"net/http"

	tykctx "github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/user"
)

// setSessionForTest injects a session into the request context for unit tests.
// It bypasses config.Global() to avoid requiring a running gateway.
// Only use in tests — production code must go through ctxSetSession.
func setSessionForTest(r *http.Request, session *user.SessionState) {
	ctx := context.WithValue(r.Context(), tykctx.SessionData, session)
	*r = *r.WithContext(ctx)
}
