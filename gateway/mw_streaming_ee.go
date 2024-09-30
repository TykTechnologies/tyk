//go:build ee || dev

// Provides StreamingMiddleware
package gateway

import (
	"github.com/TykTechnologies/tyk/internal/middleware/stream"
)

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	spec := baseMid.Spec
	streamSpec := stream.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)
	streamMw := stream.NewStreamingMiddleware(baseMid.Gw, baseMid, streamSpec)
	return WrapMiddleware(baseMid, streamMw)
}
