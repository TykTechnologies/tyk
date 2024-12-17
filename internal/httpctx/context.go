package httpctx

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

type Value[T any] struct {
	Key any
}

func NewValue[T any](key any) *Value[T] {
	return &Value[T]{Key: key}
}

func (v *Value[T]) Get(r *http.Request) (res T) {
	if val := r.Context().Value(v.Key); val != nil {
		res, _ = val.(T)
	}
	return
}

func (v *Value[T]) Set(r *http.Request, val T) *http.Request {
	ctx := context.WithValue(r.Context(), v.Key, val)
	h := r.WithContext(ctx)
	*r = *h
	return h
}

var selfLoopingValue = NewValue[bool](ctx.SelfLooping)

// SetSelfLooping updates the request context with a boolean value indicating whether the request is in a self-looping state.
func SetSelfLooping(r *http.Request, value bool) {
	r = selfLoopingValue.Set(r, value)
}

// IsSelfLooping returns true if the request is flagged as self-looping, indicating it originates and targets the same service.
func IsSelfLooping(r *http.Request) bool {
	return selfLoopingValue.Get(r)
}
