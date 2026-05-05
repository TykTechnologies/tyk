package httpctx

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
)

var selfLoopingValue = NewValue[bool](ctx.SelfLooping)

// SetSelfLooping updates the request context with a boolean value indicating whether the request is in a self-looping state.
func SetSelfLooping(r *http.Request, value bool) {
	selfLoopingValue.Set(r, value)
}

// IsSelfLooping returns true if the request is flagged as self-looping, indicating it originates and targets the same service.
func IsSelfLooping(r *http.Request) bool {
	return selfLoopingValue.Get(r)
}

// Unexported context-key types — the standard Go idiom to avoid collisions
// across packages that may share the same request context.
type callingSpecKey struct{}
type skipAuthKey struct{}

// SetCallingSpec stores the immediately-calling APIDef on a tyk:// loop hop.
// NOT transitive — chained loops MUST overwrite, not nest, otherwise transitive
// trust elevates across hops (RFC §16 step 7).
func SetCallingSpec(r *http.Request, spec *apidef.APIDefinition) *http.Request {
	c := context.WithValue(r.Context(), callingSpecKey{}, spec)
	return r.WithContext(c)
}

// GetCallingSpec returns the immediately-calling APIDef stored on the request
// context, or nil if no calling spec has been recorded.
func GetCallingSpec(r *http.Request) *apidef.APIDefinition {
	if v, ok := r.Context().Value(callingSpecKey{}).(*apidef.APIDefinition); ok {
		return v
	}
	return nil
}

// SetSkipAuth marks the request so that downstream auth middlewares short-circuit
// via the shared skip-auth helper (RFC §10.2 option c).
func SetSkipAuth(r *http.Request) *http.Request {
	c := context.WithValue(r.Context(), skipAuthKey{}, true)
	return r.WithContext(c)
}

// IsAuthSkipped returns true if SetSkipAuth has been applied to this request.
func IsAuthSkipped(r *http.Request) bool {
	v, _ := r.Context().Value(skipAuthKey{}).(bool)
	return v
}
