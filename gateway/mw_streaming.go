//go:build !ee
// +build !ee

// Provides getStreamingMiddleware
package gateway

func getStreamingMiddleware(baseMid *BaseMiddleware) TykMiddleware {
	return nil
}
