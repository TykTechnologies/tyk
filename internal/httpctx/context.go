package httpctx

import (
	"context"
	"net/http"
)

type Value[T any] struct {
	Key any
}

// SW-REQ-028
func NewValue[T any](key any) *Value[T] {
	return &Value[T]{Key: key}
}

// SW-REQ-028
func (v *Value[T]) Get(r *http.Request) (res T) {
	if val := r.Context().Value(v.Key); val != nil {
		res, _ = val.(T)
	}
	return
}

// SW-REQ-028
func (v *Value[T]) Set(r *http.Request, val T) *http.Request {
	ctx := context.WithValue(r.Context(), v.Key, val)
	h := r.WithContext(ctx)
	*r = *h
	return h
}
