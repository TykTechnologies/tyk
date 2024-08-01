package httputil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsGrpcStreaming(t *testing.T) {
	// Happy path
	req := &http.Request{
		ContentLength: -1,
		Header:        http.Header{headerContentType: []string{"application/grpc"}},
	}
	assert.True(t, IsGrpcStreaming(req))

	// Unhappy path - wrong content length
	req = &http.Request{
		ContentLength: 0,
		Header:        http.Header{headerContentType: []string{"application/grpc"}},
	}
	assert.False(t, IsGrpcStreaming(req))

	// Unhappy path - wrong content type
	req = &http.Request{
		ContentLength: -1,
		Header:        http.Header{headerContentType: []string{"text/plain"}},
	}
	assert.False(t, IsGrpcStreaming(req))
}

func TestIsSseStreamingResponse(t *testing.T) {
	// Happy path
	resp := &http.Response{
		Header: http.Header{headerContentType: []string{"text/event-stream"}},
	}
	assert.True(t, IsSseStreamingResponse(resp))

	// Unhappy path - wrong content type
	resp = &http.Response{
		Header: http.Header{headerContentType: []string{"application/json"}},
	}
	assert.False(t, IsSseStreamingResponse(resp))
}

func TestIsUpgrade(t *testing.T) {
	// Happy path
	req := &http.Request{
		Header: http.Header{
			headerConnection: []string{"Upgrade"},
			headerUpgrade:    []string{"websocket"},
		},
	}
	upgradeType, ok := IsUpgrade(req)
	assert.True(t, ok)
	assert.Equal(t, "websocket", upgradeType)

	// Unhappy path - wrong connection header
	req = &http.Request{
		Header: http.Header{
			headerConnection: []string{"keep-alive"},
			headerUpgrade:    []string{"websocket"},
		},
	}
	upgradeType, ok = IsUpgrade(req)
	assert.False(t, ok)
	assert.Empty(t, upgradeType)

	// Unhappy path - missing upgrade header
	req = &http.Request{
		Header: http.Header{
			headerConnection: []string{"Upgrade"},
		},
	}
	upgradeType, ok = IsUpgrade(req)
	assert.False(t, ok)
	assert.Empty(t, upgradeType)
}

func TestIsStreamingRequest(t *testing.T) {
	// Happy path - gRPC streaming
	req := &http.Request{
		ContentLength: -1,
		Header:        http.Header{headerContentType: []string{"application/grpc"}},
	}
	assert.True(t, IsStreamingRequest(req))

	// Happy path - WebSocket upgrade
	req = &http.Request{
		Header: http.Header{
			headerConnection: []string{"Upgrade"},
			headerUpgrade:    []string{"websocket"},
		},
	}
	assert.True(t, IsStreamingRequest(req))

	// Unhappy path - not streaming
	req = &http.Request{
		Header: http.Header{
			headerConnection: []string{"keep-alive"},
		},
	}
	assert.False(t, IsStreamingRequest(req))
}

func TestIsStreamingResponse(t *testing.T) {
	// Happy path - SSE streaming
	resp := &http.Response{
		Header: http.Header{headerContentType: []string{"text/event-stream"}},
	}
	assert.True(t, IsStreamingResponse(resp))

	// Unhappy path - not streaming
	resp = &http.Response{
		Header: http.Header{headerContentType: []string{"application/json"}},
	}
	assert.False(t, IsStreamingResponse(resp))
}
