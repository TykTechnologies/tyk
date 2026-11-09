package httputil_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

func TestTransferEncoding(t *testing.T) {
	checkTransferEncoding := func(in []string) bool {
		return httputil.HasTransferEncoding(&http.Request{
			TransferEncoding: in,
		})
	}

	assert.True(t, checkTransferEncoding([]string{"something-else"}))
	assert.True(t, checkTransferEncoding([]string{"chunked"}))
	assert.False(t, checkTransferEncoding([]string{}))
	assert.False(t, checkTransferEncoding(nil))
}

func TestForwardedScheme(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		forwarded []string
		tls       bool
		want      string
	}{
		{name: "plain connection", want: "http"},
		{name: "TLS connection", tls: true, want: "https"},
		{name: "terminated upstream", forwarded: []string{"https"}, want: "https"},
		{name: "case and spaces", forwarded: []string{" HTTPS "}, want: "https"},
		{name: "last hop wins", forwarded: []string{"https, http"}, want: "http"},
		{name: "last of repeated headers wins", forwarded: []string{"http", "https"}, want: "https"},
		{name: "unknown value falls back to plain", forwarded: []string{"javascript"}, want: "http"},
		{name: "unknown value falls back to TLS", forwarded: []string{"ftp"}, tls: true, want: "https"},
		{name: "empty value falls back", forwarded: []string{""}, want: "http"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://gateway.example/", nil)
			for _, value := range test.forwarded {
				req.Header.Add("X-Forwarded-Proto", value)
			}
			if test.tls {
				req.TLS = &tls.ConnectionState{}
			}
			assert.Equal(t, test.want, httputil.ForwardedScheme(req))
		})
	}
}
