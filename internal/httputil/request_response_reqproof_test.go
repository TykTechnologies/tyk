package httputil_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
)

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// MCDC SYS-REQ-171: http_request_response_helpers_operation_terminal=T => TRUE
// MCDC SW-REQ-158: http_request_response_helpers_operation_terminal=T => TRUE
// STK-REQ-083:STK-REQ-083-AC-01:acceptance
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestHTTPRequestResponseHelpersReqProof(t *testing.T) {
	t.Run("transfer encoding helpers", func(t *testing.T) {
		tests := []struct {
			name     string
			encoding []string
			want     string
			wantHas  bool
		}{
			{name: "first non-empty transfer encoding", encoding: []string{"", "gzip"}, want: "gzip", wantHas: true},
			{name: "no transfer encoding", encoding: []string{"", ""}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := &http.Request{TransferEncoding: tt.encoding}
				assert.Equal(t, tt.want, httputil.TransferEncoding(req))
				assert.Equal(t, tt.wantHas, httputil.HasTransferEncoding(req))
			})
		}
	})

	t.Run("request scheme helpers", func(t *testing.T) {
		tests := []struct {
			name           string
			forwardedProto string
			tls            *tls.ConnectionState
			want           string
		}{
			{name: "forwarded proto wins", forwardedProto: "ws", tls: &tls.ConnectionState{}, want: "ws"},
			{name: "tls request", tls: &tls.ConnectionState{}, want: "https"},
			{name: "plain request", want: "http"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := &http.Request{
					Header: make(http.Header),
					TLS:    tt.tls,
				}
				if tt.forwardedProto != "" {
					req.Header.Set(header.XForwardProto, tt.forwardedProto)
				}

				assert.Equal(t, tt.want, httputil.RequestScheme(req))
			})
		}
	})

	t.Run("cors preflight marker", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			header string
			want   bool
		}{
			{name: "options with requested method", method: http.MethodOptions, header: http.MethodPost, want: true},
			{name: "options without requested method", method: http.MethodOptions},
			{name: "get with requested method", method: http.MethodGet, header: http.MethodPost},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := &http.Request{
					Method: tt.method,
					Header: make(http.Header),
				}
				if tt.header != "" {
					req.Header.Set("Access-Control-Request-Method", tt.header)
				}

				assert.Equal(t, tt.want, httputil.IsCORSPreflightRequest(req))
			})
		}
	})

	t.Run("local error responses", func(t *testing.T) {
		tests := []struct {
			name   string
			handle func(http.ResponseWriter, *http.Request)
			status int
		}{
			{name: "entity too large", handle: httputil.EntityTooLarge, status: http.StatusRequestEntityTooLarge},
			{name: "length required", handle: httputil.LengthRequired, status: http.StatusLengthRequired},
			{name: "internal server error", handle: httputil.InternalServerError, status: http.StatusInternalServerError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				tt.handle(w, nil)

				result := w.Result()
				defer result.Body.Close()

				body, err := io.ReadAll(result.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.status, result.StatusCode)
				assert.Contains(t, string(body), http.StatusText(tt.status))
			})
		}
	})

	t.Run("response transfer encoding removal", func(t *testing.T) {
		tests := []struct {
			name string
			have []string
			drop string
			want []string
		}{
			{name: "remove matching encoding", have: []string{"chunked", "gzip"}, drop: "chunked", want: []string{"gzip"}},
			{name: "preserve when missing", have: []string{"chunked", "gzip"}, drop: "deflate", want: []string{"chunked", "gzip"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				response := &http.Response{TransferEncoding: append([]string(nil), tt.have...)}
				httputil.RemoveResponseTransferEncoding(response, tt.drop)
				assert.Equal(t, tt.want, response.TransferEncoding)
			})
		}
	})
}
