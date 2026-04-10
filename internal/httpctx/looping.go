package httpctx

import (
	"net/http"

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
