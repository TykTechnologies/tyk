//go:build ee || dev

// Provides StreamingMiddleware
package gateway

import (
	"github.com/TykTechnologies/tyk/internal/middleware/streamv1"
)

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	spec := baseMid.Spec
	streamSpec := streamv1.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)
	streamMw := streamv1.NewMiddleware(baseMid.Gw, baseMid, streamSpec)
	return WrapMiddleware(baseMid, streamMw)
}
