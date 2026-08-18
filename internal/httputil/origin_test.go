package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "lowercase and default HTTPS port", in: "HTTPS://EXAMPLE.COM:443", want: "https://example.com", ok: true},
		{name: "non-default port", in: "http://Example.COM:8080", want: "http://example.com:8080", ok: true},
		{name: "IPv6", in: "https://[2001:0db8::1]:443", want: "https://[2001:db8::1]", ok: true},
		{name: "null", in: "null"},
		{name: "wildcard", in: "https://*.example.com"},
		{name: "path", in: "https://example.com/"},
		{name: "credentials", in: "https://user@example.com"},
		{name: "query", in: "https://example.com?x=1"},
		{name: "fragment", in: "https://example.com#x"},
		{name: "non HTTP", in: "file://example.com"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CanonicalOrigin(test.in)
			if !test.ok {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestExternalOrigin_TrustsOnlyImmediatePeerAndRightmostValues(t *testing.T) {
	t.Parallel()

	newRequest := func() *http.Request {
		req := httptest.NewRequest("POST", "http://internal:8080/mcp", nil)
		req.RemoteAddr = "10.0.0.9:1234"
		req.Header.Add("Forwarded", "for=attacker;proto=http;host=evil.example, for=10.0.0.8;proto=https;host=API.EXAMPLE:443")
		req.Header.Set("X-Forwarded-Proto", "http, http")
		req.Header.Set("X-Forwarded-Host", "evil.example, also-evil.example")
		return req
	}

	origin, err := ExternalOrigin(newRequest(), []string{"10.0.0.0/24"})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example", origin)

	origin, err = ExternalOrigin(newRequest(), []string{"192.0.2.0/24"})
	require.NoError(t, err)
	assert.Equal(t, "http://internal:8080", origin)
}

func TestExternalOrigin_UsesRightmostXForwardedValues(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("POST", "http://internal/mcp", nil)
	req.RemoteAddr = "[2001:db8::2]:1234"
	req.Header.Set("X-Forwarded-Proto", "http, https")
	req.Header.Set("X-Forwarded-Host", "evil.example, [2001:db8::1]:443")

	origin, err := ExternalOrigin(req, []string{"2001:db8::/64"})
	require.NoError(t, err)
	assert.Equal(t, "https://[2001:db8::1]", origin)
}
