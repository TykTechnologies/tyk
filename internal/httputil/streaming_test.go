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

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:determinism:nominal
func TestIsGrpcStreaming(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		contentType   string
		want          bool
	}{
		{name: "grpc streaming", contentLength: -1, contentType: "application/grpc", want: true},
		{name: "grpc fixed length", contentLength: 0, contentType: "application/grpc"},
		{name: "streaming non-grpc", contentLength: -1, contentType: "text/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequestWithHeaders(t, tt.contentLength, map[string]string{headerContentType: tt.contentType})
			assert.Equal(t, tt.want, IsGrpcStreaming(req))
		})
	}
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// STK-REQ-082:STK-REQ-082-AC-01:acceptance
// STK-REQ-082:error_handling:negative
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:error_handling:nominal
// SW-REQ-157:error_handling:negative
// SW-REQ-157:determinism:nominal
func TestIsSSEContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"exact match", "text/event-stream", true},
		{"charset with space", "text/event-stream; charset=utf-8", true},
		{"charset without space", "text/event-stream;charset=utf-8", true},
		{"application/json", "application/json", false},
		{"empty string", "", false},
		{"text/plain", "text/plain", false},
		{"partial match", "text/event-streamx", false},
		{"malformed parameter", `text/event-stream; charset="`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsSSEContentType(tt.ct))
		})
	}
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:determinism:nominal
func TestIsSSEStreamingResponse(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "sse exact", contentType: "text/event-stream", want: true},
		{name: "sse with charset", contentType: "text/event-stream; charset=utf-8", want: true},
		{name: "json", contentType: "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newResponseWithHeaders(t, map[string]string{headerContentType: tt.contentType})
			assert.Equal(t, tt.want, IsSSEStreamingResponse(resp))
		})
	}
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:determinism:nominal
func TestIsUpgrade(t *testing.T) {
	tests := []struct {
		name        string
		connection  string
		upgrade     string
		wantUpgrade string
		wantOK      bool
	}{
		{name: "websocket upgrade", connection: "Upgrade", upgrade: "websocket", wantUpgrade: "websocket", wantOK: true},
		{name: "connection not upgrade", connection: "keep-alive", upgrade: "websocket"},
		{name: "upgrade header missing", connection: "Upgrade"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{headerConnection: tt.connection}
			if tt.upgrade != "" {
				headers[headerUpgrade] = tt.upgrade
			}
			upgradeType, ok := IsUpgrade(newRequestWithHeaders(t, 0, headers))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantUpgrade, upgradeType)
		})
	}
}

// Reproduces: KI-HTTPUTIL-UPGRADE-CONNECTION-TOKEN
// Verifies: SYS-REQ-170
func TestKnownIssue_IsUpgradeIgnoresConnectionTokenList(t *testing.T) {
	req := newRequestWithHeaders(t, 0, map[string]string{
		headerConnection: "keep-alive, Upgrade",
		headerUpgrade:    "websocket",
	})

	upgradeType, ok := IsUpgrade(req)

	assert.False(t, ok)
	assert.Empty(t, upgradeType)
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:determinism:nominal
func TestIsStreamingRequest(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		headers       map[string]string
		want          bool
	}{
		{name: "grpc streaming", contentLength: -1, headers: map[string]string{headerContentType: "application/grpc"}, want: true},
		{name: "websocket upgrade", headers: map[string]string{headerConnection: "Upgrade", headerUpgrade: "websocket"}, want: true},
		{name: "keep alive", headers: map[string]string{headerConnection: "keep-alive"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsStreamingRequest(newRequestWithHeaders(t, tt.contentLength, tt.headers)))
		})
	}
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:determinism:nominal
func TestIsStreamingResponse(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "sse exact", contentType: "text/event-stream", want: true},
		{name: "sse with charset", contentType: "text/event-stream; charset=utf-8", want: true},
		{name: "json", contentType: "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newResponseWithHeaders(t, map[string]string{headerContentType: tt.contentType})
			assert.Equal(t, tt.want, IsStreamingResponse(resp))
		})
	}
}

// Verifies: STK-REQ-082, SYS-REQ-170, SW-REQ-157
// MCDC SYS-REQ-170: http_streaming_helpers_operation_terminal=T => TRUE
// MCDC SW-REQ-157: http_streaming_helpers_operation_terminal=T => TRUE
// STK-REQ-082:STK-REQ-082-AC-01:acceptance
// SW-REQ-157:nominal:nominal
// SW-REQ-157:boundary:nominal
// SW-REQ-157:error_handling:negative
// SW-REQ-157:determinism:nominal
func TestHTTPStreamingHelpersReqProof(t *testing.T) {
	t.Run("grpc request classification", func(t *testing.T) {
		tests := []struct {
			name          string
			contentLength int64
			contentType   string
			want          bool
		}{
			{name: "streaming grpc", contentLength: -1, contentType: "application/grpc", want: true},
			{name: "fixed length grpc", contentLength: 0, contentType: "application/grpc"},
			{name: "streaming non-grpc", contentLength: -1, contentType: "text/plain"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := newRequestWithHeaders(t, tt.contentLength, map[string]string{headerContentType: tt.contentType})
				assert.Equal(t, tt.want, IsGrpcStreaming(req))
			})
		}
	})

	t.Run("sse content type parsing", func(t *testing.T) {
		tests := []struct {
			name string
			ct   string
			want bool
		}{
			{name: "exact event stream", ct: "text/event-stream", want: true},
			{name: "event stream with charset", ct: "text/event-stream; charset=utf-8", want: true},
			{name: "json fallback", ct: "application/json"},
			{name: "malformed parameter fallback", ct: `text/event-stream; charset="`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, IsSSEContentType(tt.ct))
			})
		}
	})

	t.Run("sse response classification", func(t *testing.T) {
		tests := []struct {
			name        string
			contentType string
			want        bool
		}{
			{name: "sse response", contentType: "text/event-stream; charset=utf-8", want: true},
			{name: "json response", contentType: "application/json"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp := newResponseWithHeaders(t, map[string]string{headerContentType: tt.contentType})
				assert.Equal(t, tt.want, IsSSEStreamingResponse(resp))
				assert.Equal(t, tt.want, IsStreamingResponse(resp))
			})
		}
	})

	t.Run("upgrade request classification", func(t *testing.T) {
		tests := []struct {
			name        string
			connection  string
			upgrade     string
			wantUpgrade string
			wantOK      bool
		}{
			{name: "websocket upgrade", connection: " Upgrade ", upgrade: "WebSocket", wantUpgrade: "websocket", wantOK: true},
			{name: "non-upgrade connection", connection: "keep-alive", upgrade: "websocket"},
			{name: "missing upgrade header", connection: "Upgrade"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				headers := map[string]string{headerConnection: tt.connection}
				if tt.upgrade != "" {
					headers[headerUpgrade] = tt.upgrade
				}

				upgradeType, ok := IsUpgrade(newRequestWithHeaders(t, 0, headers))
				assert.Equal(t, tt.wantOK, ok)
				assert.Equal(t, tt.wantUpgrade, upgradeType)
			})
		}
	})

	t.Run("aggregate request classification", func(t *testing.T) {
		tests := []struct {
			name          string
			contentLength int64
			headers       map[string]string
			want          bool
		}{
			{
				name:          "grpc streaming request",
				contentLength: -1,
				headers:       map[string]string{headerContentType: "application/grpc"},
				want:          true,
			},
			{
				name:    "websocket streaming request",
				headers: map[string]string{headerConnection: "Upgrade", headerUpgrade: "websocket"},
				want:    true,
			},
			{
				name:    "non-streaming request",
				headers: map[string]string{headerConnection: "keep-alive", headerContentType: "application/json"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := newRequestWithHeaders(t, tt.contentLength, tt.headers)
				assert.Equal(t, tt.want, IsStreamingRequest(req))
			})
		}
	})
}
