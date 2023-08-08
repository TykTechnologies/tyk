//go:build v52
// +build v52

package gateway

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/trace"
)

type TraceMiddleware struct {
	TykMiddleware
}

func (tr TraceMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	var otelEnabled bool

	baseMw := tr.Base()
	if baseMw == nil {
		goto done
	}

	otelEnabled = baseMw.Gw.GetConfig().OpenTelemetry.Enabled

	switch {
	case trace.IsEnabled():
		span, ctx := trace.Span(r.Context(),
			tr.Name(),
		)
		defer span.Finish()

		setContext(r, ctx)

	case otelEnabled:

		var span otel.Span

		if baseMw.Spec.DetailedTracing {
			var ctx context.Context
			ctx, span = baseMw.Gw.TracerProvider.Tracer().Start(r.Context(), tr.Name())
			defer span.End()
			setContext(r, ctx)
		} else {
			span = otel.SpanFromContext(r.Context())
		}

		err, i := tr.TykMiddleware.ProcessRequest(w, r, conf)
		if err != nil {
			span.SetStatus(otel.SPAN_STATUS_ERROR, err.Error())
		}

		attrs := ctxGetSpanAttributes(r, tr.TykMiddleware.Name())
		if len(attrs) > 0 {
			span.SetAttributes(attrs...)
		}

		return err, i
	}

done:
	return tr.TykMiddleware.ProcessRequest(w, r, conf)
}
