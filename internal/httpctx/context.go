package httpctx

import (
	"context"
	"net/http"
)

type Value[T any] struct {
	Key any
}

func NewValue[T any](key any) *Value[T] {
	return &Value[T]{Key: key}
}

func (v *Value[T]) Get(r *http.Request) (res T, ok bool) {
	if val := r.Context().Value(v.Key); val != nil {
		res, ok = val.(T)
	}
	return
}

func (v *Value[T]) Set(r *http.Request, val T) *http.Request {
	ctx := context.WithValue(r.Context(), v.Key, val)
	return r.WithContext(ctx)
}
