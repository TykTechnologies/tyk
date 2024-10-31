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
