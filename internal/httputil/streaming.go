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
func IsGrpcStreaming(r *http.Request) bool {
	return r.ContentLength == -1 && r.Header.Get(headerContentType) == "application/grpc"
}

// IsSseContentType returns true if the Content-Type value designates SSE.
// It handles both exact matches (e.g. "text/event-stream") and values with
// parameters (e.g. "text/event-stream; charset=utf-8").
func IsSseContentType(ct string) bool {
	if ct == "text/event-stream" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "text/event-stream"
}

// IsSseStreamingResponse returns true if the response designates SSE streaming.
func IsSseStreamingResponse(r *http.Response) bool {
	return IsSseContentType(r.Header.Get(headerContentType))
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
