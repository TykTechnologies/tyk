package httputil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/TykTechnologies/tyk/internal/httputil"
)

const (
	headerContentType = "Content-Type"
	headerUpgrade     = "Upgrade"
	headerConnection  = "Connection"
)

// Helper function to create a request with specified headers
func newRequestWithHeaders(tb testing.TB, contentLength int64, headers map[string]string) *http.Request {
	tb.Helper()
	req := &http.Request{
		ContentLength: contentLength,
		Header:        make(http.Header),
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

// Helper function to create a response with specified headers
func newResponseWithHeaders(tb testing.TB, headers map[string]string) *http.Response {
	tb.Helper()
	resp := &http.Response{
		Header: make(http.Header),
	}
	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	return resp
}

func TestIsGrpcStreaming(t *testing.T) {
	assert.True(t, IsGrpcStreaming(newRequestWithHeaders(t, -1, map[string]string{headerContentType: "application/grpc"})))
	assert.False(t, IsGrpcStreaming(newRequestWithHeaders(t, 0, map[string]string{headerContentType: "application/grpc"})))
	assert.False(t, IsGrpcStreaming(newRequestWithHeaders(t, -1, map[string]string{headerContentType: "text/plain"})))
}

func TestIsSseStreamingResponse(t *testing.T) {
	assert.True(t, IsSseStreamingResponse(newResponseWithHeaders(t, map[string]string{headerContentType: "text/event-stream"})))
	assert.False(t, IsSseStreamingResponse(newResponseWithHeaders(t, map[string]string{headerContentType: "application/json"})))
}

func TestIsUpgrade(t *testing.T) {
	req := newRequestWithHeaders(t, 0, map[string]string{headerConnection: "Upgrade", headerUpgrade: "websocket"})
	upgradeType, ok := IsUpgrade(req)
	assert.True(t, ok)
	assert.Equal(t, "websocket", upgradeType)

	req = newRequestWithHeaders(t, 0, map[string]string{headerConnection: "keep-alive, Upgrade", headerUpgrade: "websocket"})
	upgradeType, ok = IsUpgrade(req)
	assert.True(t, ok)
	assert.Equal(t, "websocket", upgradeType)

	req = newRequestWithHeaders(t, 0, map[string]string{headerConnection: "keep-alive", headerUpgrade: "websocket"})
	upgradeType, ok = IsUpgrade(req)
	assert.False(t, ok)
	assert.Empty(t, upgradeType)

	req = newRequestWithHeaders(t, 0, map[string]string{headerConnection: "keep-alive, Upgrade"})
	upgradeType, ok = IsUpgrade(req)
	assert.False(t, ok)
	assert.Empty(t, upgradeType)

	req = newRequestWithHeaders(t, 0, map[string]string{headerConnection: "Upgrade"})
	upgradeType, ok = IsUpgrade(req)
	assert.False(t, ok)
	assert.Empty(t, upgradeType)
}

func TestIsStreamingRequest(t *testing.T) {
	assert.True(t, IsStreamingRequest(newRequestWithHeaders(t, -1, map[string]string{headerContentType: "application/grpc"})))
	assert.True(t, IsStreamingRequest(newRequestWithHeaders(t, 0, map[string]string{headerConnection: "Upgrade", headerUpgrade: "websocket"})))
	assert.False(t, IsStreamingRequest(newRequestWithHeaders(t, 0, map[string]string{headerConnection: "keep-alive"})))
}

func TestIsStreamingResponse(t *testing.T) {
	assert.True(t, IsStreamingResponse(newResponseWithHeaders(t, map[string]string{headerContentType: "text/event-stream"})))
	assert.False(t, IsStreamingResponse(newResponseWithHeaders(t, map[string]string{headerContentType: "application/json"})))
}
