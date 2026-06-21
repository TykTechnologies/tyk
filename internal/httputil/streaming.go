package httputil

import (
	"mime"
	"net/http"
	"strings"
)

const (
	headerContentType = "Content-Type"
	headerUpgrade     = "Upgrade"
	headerConnection  = "Connection"
)

// IsGrpcStreaming returns true if the request designates gRPC streaming.
// SW-REQ-157
func IsGrpcStreaming(r *http.Request) bool {
	return r.ContentLength == -1 && r.Header.Get(headerContentType) == "application/grpc"
}

// IsSSEContentType returns true if the Content-Type value designates SSE.
// It handles both exact matches (e.g. "text/event-stream") and values with
// parameters (e.g. "text/event-stream; charset=utf-8").
// SW-REQ-157
func IsSSEContentType(ct string) bool {
	if ct == "text/event-stream" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "text/event-stream"
}

// IsSSEStreamingResponse returns true if the response designates SSE streaming.
// SW-REQ-157
func IsSSEStreamingResponse(r *http.Response) bool {
	return IsSSEContentType(r.Header.Get(headerContentType))
}

// IsUpgrade checks if the request is an upgrade request and returns the upgrade type.
// SW-REQ-157
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
// SW-REQ-157
func IsStreamingRequest(r *http.Request) bool {
	_, upgrade := IsUpgrade(r)
	return upgrade || IsGrpcStreaming(r)
}

// IsStreamingResponse returns true if the response designates streaming (SSE).
// SW-REQ-157
func IsStreamingResponse(r *http.Response) bool {
	return IsSSEStreamingResponse(r)
}
