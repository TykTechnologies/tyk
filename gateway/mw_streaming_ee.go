//go:build ee || dev

// Provides StreamingMiddleware
package gateway

import (
	"github.com/TykTechnologies/tyk/ee/middleware/streams"
)

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	spec := baseMid.Spec
	streamSpec := streams.NewAPISpec(spec.APIID, spec.Name, spec.IsOAS, spec.OAS, spec.StripListenPath)

	streamAnalyticsFactory := NewStreamAnalyticsFactory(baseMid.logger.Dup(), baseMid.Gw, spec)
	streamMw := streams.NewMiddleware(baseMid.Gw, baseMid, streamSpec, streamAnalyticsFactory)
	return WrapMiddleware(baseMid, streamMw)
}
