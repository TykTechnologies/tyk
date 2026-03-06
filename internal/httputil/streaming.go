package httputil

import (
	"mime"
	"net/http"
	"net/textproto"
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

// IsSSEContentType returns true if the Content-Type value designates SSE.
// It handles both exact matches (e.g. "text/event-stream") and values with
// parameters (e.g. "text/event-stream; charset=utf-8").
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
func IsSSEStreamingResponse(r *http.Response) bool {
	return IsSSEContentType(r.Header.Get(headerContentType))
}

// IsUpgrade checks if the request is an upgrade request and returns the upgrade type.
func IsUpgrade(req *http.Request) (string, bool) {
	if !headerContainsTokenIgnoreCase(req.Header, headerConnection, "Upgrade") {
		return "", false
	}

	upgrade := strings.ToLower(strings.TrimSpace(req.Header.Get(headerUpgrade)))
	if upgrade != "" {
		return upgrade, true
	}

	return "", false
}

func headerContainsTokenIgnoreCase(h http.Header, key, token string) bool {
	for _, t := range headerTokens(h, key) {
		if strings.EqualFold(t, token) {
			return true
		}
	}
	return false
}

func headerTokens(h http.Header, key string) []string {
	key = textproto.CanonicalMIMEHeaderKey(key)
	var tokens []string
	for _, v := range h[key] {
		v = strings.TrimSpace(v)
		for _, t := range strings.Split(v, ",") {
			t = strings.TrimSpace(t)
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// IsStreamingRequest returns true if the request designates streaming (gRPC or WebSocket).
func IsStreamingRequest(r *http.Request) bool {
	_, upgrade := IsUpgrade(r)
	return upgrade || IsGrpcStreaming(r)
}

// IsStreamingResponse returns true if the response designates streaming (SSE).
func IsStreamingResponse(r *http.Response) bool {
	return IsSSEStreamingResponse(r)
}
