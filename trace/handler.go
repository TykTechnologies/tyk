package trace

import (
	"net/http"
	"strconv"

	"github.com/TykTechnologies/tyk/request"
	"github.com/opentracing/opentracing-go"
)

// Handler implements http.Handler interface that wraps another http.Handler and
// adds opentracing support.
//
// Use NewHandler function to provide the wrapped http.Handler and the operation
// on which it will be traced by.
type Handler struct {
	r    http.Handler
	ops  Operation
	opts []opentracing.StartSpanOption
	// Is set to true, it will add tags to the span tracting request information.
	// The tags added are from_ip, method, endpointraw_url and size
	injectRequestMetadata bool
}

// NewHandler returns a Handler instance that instruments h for opentracing.
func NewHandler(ops Operation, h http.Handler, opts ...opentracing.StartSpanOption) Handler {
	return Handler{r: h, ops: ops, opts: opts}
}

// NewHandlerWithInjection like NewHandler but injects tags with request metadata.
func NewHandlerWithInjection(ops Operation, h http.Handler, opts ...opentracing.StartSpanOption) Handler {
	return Handler{r: h, ops: ops, opts: opts, injectRequestMetadata: true}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	opts := h.opts
	if h.injectRequestMetadata {
		opts = append(opts,
			opentracing.Tags{
				"from_ip":  request.RealIP(r),
				"method":   r.Method,
				"endpoint": r.URL.Path,
				"raw_url":  r.URL.String(),
				"size":     strconv.Itoa(int(r.ContentLength)),
			},
		)
	}
	span, ctx := Span(r.Context(), h.ops, opts...)
	defer span.Finish()
	h.r.ServeHTTP(w, r.WithContext(ctx))
}
