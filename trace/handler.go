package trace

import "net/http"

// Handle returns a http.Handler with root opentracting setup. This should be
// the topmost handler.
func Handle(service string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, req := Root(service, r)
		defer span.Finish()
		h.ServeHTTP(w, req)
	})
}
