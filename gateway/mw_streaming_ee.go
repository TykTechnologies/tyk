//go:build ee || dev

// Provides StreamingMiddleware
package gateway

import (
	"github.com/TykTechnologies/tyk/ee/internal/middleware/streams"
)

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	spec := baseMid.Spec
	streamSpec := streams.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)
	streamMw := streams.NewMiddleware(baseMid.Gw, baseMid, streamSpec)
	return WrapMiddleware(baseMid, streamMw)
}
