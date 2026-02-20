package httputil

import (
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

// IsSseStreamingResponse returns true if the response designates SSE streaming.
func IsSseStreamingResponse(r *http.Response) bool {
	return r.Header.Get(headerContentType) == "text/event-stream"
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
	return IsSseStreamingResponse(r)
}
