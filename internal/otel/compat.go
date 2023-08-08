//go:build !v52
// +build !v52

package otel

import "context"

// Just ignore this file. These are non-functional shims to resolve types.
// The individual values are not consumed or produced.

type TracerProvider interface{}

type SpanAttribute struct{}

var dummy SpanAttribute

func APIKeyAttribute(string) SpanAttribute        { return dummy }
func APIVersionAttribute(string) SpanAttribute        { return dummy }
func APIKeyAliasAttribute(string) SpanAttribute   { return dummy }
func OAuthClientIDAttribute(string) SpanAttribute { return dummy }

// span const
const (
	SPAN_STATUS_OK    = "ok"
	SPAN_STATUS_ERROR = "error"
	SPAN_STATUS_UNSET = "unset"
)

const NON_VERSIONED = "Non Versioned"

type Span struct{}

func SpanFromContext(_ context.Context) Span {
	return Span{}
}

func ContextWithSpan(ctx context.Context, _ Span) context.Context {
	return ctx
}
