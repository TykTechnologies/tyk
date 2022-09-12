package trace

import (
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"net/http"
)

// Handle returns a http.Handler with root opentracting setup. This should be
// the topmost handler.
func Handle(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, req := Root(service, r)
		defer span.End()
		opStr := r.Method + " " +r.URL.Path
		otelHandler := otelhttp.NewHandler(h,opStr)
		otelHandler.ServeHTTP(w, req)
	})
}
