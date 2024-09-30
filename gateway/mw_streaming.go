//go:build !ee && !dev

// Provides getStreamingMiddleware
package gateway

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	return nil
}
