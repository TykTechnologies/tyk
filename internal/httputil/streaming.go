package httputil

import (
	"net/http"
	"strings"
)

const (
	headerContentType = "Content-Type"
	headerUpgrade     = "Upgrade"
	headerConnection  = "Connection"
)

// IsGrpcStreaming returns true if the request designates gRPC streaming.
func IsGrpcStreaming(r *http.Request) bool {
	return r.ContentLength == -1 && r.Header.Get(headerContentType) == "application/grpc"
}

// IsSseStreamingResponse returns true if the response designates SSE streaming.
func IsSseStreamingResponse(r *http.Response) bool {
	return r.Header.Get(headerContentType) == "text/event-stream"
}

// IsUpgrade checks if the request is an upgrade request and returns the upgrade type.
func IsUpgrade(req *http.Request) (string, bool) {
	connection := strings.ToLower(strings.TrimSpace(req.Header.Get(headerConnection)))
	if connection != "upgrade" {
		return "", false
	}

	upgrade := strings.ToLower(strings.TrimSpace(req.Header.Get(headerUpgrade)))
	if upgrade != "" {
		return upgrade, true
	}

	return "", false
}

// IsStreamingRequest returns true if the request designates streaming (gRPC or WebSocket).
func IsStreamingRequest(r *http.Request) bool {
	_, upgrade := IsUpgrade(r)
	return upgrade || IsGrpcStreaming(r)
}

// IsStreamingResponse returns true if the response designates streaming (SSE).
func IsStreamingResponse(r *http.Response) bool {
	return IsSseStreamingResponse(r)
}
