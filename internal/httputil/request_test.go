package httputil_test

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/httputil"
)

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// STK-REQ-083:STK-REQ-083-AC-01:acceptance
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestTransferEncoding(t *testing.T) {
	tests := []struct {
		name     string
		encoding []string
		want     string
		wantHas  bool
	}{
		{name: "custom transfer encoding", encoding: []string{"something-else"}, want: "something-else", wantHas: true},
		{name: "chunked transfer encoding", encoding: []string{"chunked"}, want: "chunked", wantHas: true},
		{name: "first non-empty transfer encoding", encoding: []string{"", "gzip"}, want: "gzip", wantHas: true},
		{name: "empty slice", encoding: []string{}},
		{name: "nil slice", encoding: nil},
		{name: "only empty values", encoding: []string{"", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{TransferEncoding: tt.encoding}
			assert.Equal(t, tt.want, httputil.TransferEncoding(req))
			assert.Equal(t, tt.wantHas, httputil.HasTransferEncoding(req))
		})
	}
}

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestRequestScheme(t *testing.T) {
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
}

// Verifies: STK-REQ-083, SYS-REQ-171, SW-REQ-158
// SW-REQ-158:nominal:nominal
// SW-REQ-158:boundary:nominal
// SW-REQ-158:determinism:nominal
func TestIsCORSPreflightRequest(t *testing.T) {
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
}
