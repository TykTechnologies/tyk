package trace

import (
	"context"
	"io"
	"net/http"
	"strconv"

	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/trace/appdash"
	"github.com/TykTechnologies/tyk/trace/jaeger"
	"github.com/opentracing/opentracing-go"
)

// NoopKey when set in context.Context it signals that we don't want to trace
// that path.
//
// This allows to dynamically enable/disable tracing in any condition by simply
// injecting this key into the context that is passed down the request pipeline.
type NoopKey = struct{}

// DisableTracing returns a new context with NoopKey set to true effectively
// disabling tracing for any spans created with the returned context.
func DisableTracing(ctx context.Context) context.Context {
	return context.WithValue(ctx, NoopKey{}, true)
}

type Tracer interface {
	Name() string
	opentracing.Tracer
	io.Closer
}

// NoopTracer wraps opentracing.NoopTracer to satisfy Tracer interface.
type NoopTracer struct {
	opentracing.NoopTracer
}

// Close implements io.Closer interface by doing nothing.
func (n NoopTracer) Close() error {
	return nil
}

func (n NoopTracer) Name() string {
	return "NoopTracer"
}

// Init returns a tracer for a given name.
func Init(name string, opts map[string]interface{}) (Tracer, error) {
	switch name {
	case appdash.Name:
		return appdash.Init(opts)
	case jaeger.Name:
		return jaeger.Init(opts)
	default:
		return NoopTracer{}, nil
	}
}

// Operation is a unit of activity performed by the gateway. Not all operations
// are covered  here , we are only interested in traceable operations
type Operation uint

// supported operations
const (

	// MainEntry this is the top most span. Definning the main entry of the request
	// to the gateway.
	// All other spans are children  of this span.
	MainEntry Operation = iota
	Api
	StripSlash
	CheckIsAPIOwner
	ControlAPICheckClientCertificate
	InstrumentationMW
	MethodNotAllowed

	HeaderInjector
	ResponseTransformMiddleware
	ResponseTransformJQMiddleware
	HeaderTransform
)

func (o Operation) String() string {
	switch o {
	case MainEntry:
		return "tyk-gateway"
	case Api:
		return "api"
	case StripSlash:
		return "strip-request-slash"
	case CheckIsAPIOwner:
		return "check-request-is-api-owner"
	case ControlAPICheckClientCertificate:
		return "check-control-api-client-certificate"
	case InstrumentationMW:
		return "instrument-request"
	case MethodNotAllowed:
		return "handle-method-not-allowed"
	case HeaderInjector:
		return "inject-headers"
	case ResponseTransformMiddleware:
		return "transform-response"
	case ResponseTransformJQMiddleware:
		return "transform-response-jq"
	case HeaderTransform:
		return "transform-header"
	default:
		return "noop"
	}
}

// MainSpan creates the entry point span. This extracts any propagated span
// found in request r or creates a new one.
//
// The returned span is injected into request context so this is available in
// all middlewares
//
// It is up to the caller to call Finish on the returned span.
func MainSpan(r *http.Request) (opentracing.Span, *http.Request) {
	mainCtx, err := opentracing.GlobalTracer().Extract(
		opentracing.TextMap,
		opentracing.HTTPHeadersCarrier(r.Header),
	)
	tags := opentracing.Tags{
		"from_ip":  request.RealIP(r),
		"method":   r.Method,
		"endpoint": r.URL.Path,
		"raw_url":  r.URL.String(),
		"size":     strconv.Itoa(int(r.ContentLength)),
	}
	if err != nil {
		// TODO log this error?
		// We just create a new span here so the log should be a warning.
		span, ctx := opentracing.StartSpanFromContext(r.Context(), MainEntry.String(), tags)
		return span, r.WithContext(ctx)
	}
	span, ctx := opentracing.StartSpanFromContext(r.Context(), MainEntry.String(),
		opentracing.ChildOf(mainCtx), tags)
	return span, r.WithContext(ctx)
}

var noop = opentracing.NoopTracer{}

func tracingIsDisabled(ctx context.Context) bool {
	if v := ctx.Value(NoopKey{}); v != nil {
		return v.(bool)
	}
	return false
}

// Span creates a new span for the given ops. If tracing is disabled in this ctx
// then a noop span is created and the same ctx is returned.
//
// Note that the returned context contains the returned span as active span. So
// any spans created form the returned context will be children of the returned
// span.
func Span(ctx context.Context, ops Operation, opts ...opentracing.StartSpanOption) (opentracing.Span, context.Context) {
	if tracingIsDisabled(ctx) {
		return noop.StartSpan(ops.String(), opts...), ctx
	}
	return opentracing.StartSpanFromContext(ctx, ops.String(), opts...)
}
