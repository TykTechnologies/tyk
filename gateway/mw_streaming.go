//go:build !ee && !dev

// Provides getStreamingMiddleware
package gateway

func getStreamingMiddleware(_ *BaseMiddleware) TykMiddleware {
	return nil
}
