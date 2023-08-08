//go:build !v52
// +build !v52

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/trace"
)

type TraceMiddleware struct {
	TykMiddleware
}

func (tr TraceMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	if trace.IsEnabled() {
		span, ctx := trace.Span(r.Context(),
			tr.Name(),
		)
		defer span.Finish()

		setContext(r, ctx)
	}

	return tr.TykMiddleware.ProcessRequest(w, r, conf)
}
