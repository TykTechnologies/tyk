package httputil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebSocketOriginChecker(t *testing.T) {
	type request struct {
		host       string
		tls        bool
		remoteAddr string
		origins    []string
		headers    map[string]string
	}

	tests := []struct {
		name    string
		opts    WebSocketOriginOptions
		req     request
		allowed bool
	}{
		{
			name:    "no origin header is accepted",
			req:     request{host: "gw.example"},
			allowed: true,
		},
		{
			name:    "own origin is accepted",
			req:     request{host: "gw.example:8080", origins: []string{"http://gw.example:8080"}},
			allowed: true,
		},
		{
			name:    "own origin over TLS is accepted",
			req:     request{host: "gw.example", tls: true, origins: []string{"https://gw.example"}},
			allowed: true,
		},
		{
			name:    "own host with another scheme is refused",
			req:     request{host: "gw.example", origins: []string{"https://gw.example"}},
			allowed: false,
		},
		{
			name:    "own origin matches case-insensitively",
			req:     request{host: "GW.example", origins: []string{"http://gw.EXAMPLE"}},
			allowed: true,
		},
		{
			name:    "other origin is refused without CORS",
			req:     request{host: "gw.example", origins: []string{"http://attacker.example"}},
			allowed: false,
		},
		{
			name:    "null origin is refused",
			req:     request{host: "gw.example", origins: []string{"null"}},
			allowed: false,
		},
		{
			name:    "malformed origin is refused",
			req:     request{host: "gw.example", origins: []string{"http://gw.example/path"}},
			allowed: false,
		},
		{
			name:    "several origin headers are refused",
			req:     request{host: "gw.example", origins: []string{"http://gw.example", "http://gw.example"}},
			allowed: false,
		},
		{
			name:    "non-ASCII origin that is not allowed is refused",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"https://good.example"}},
			req:     request{host: "gw.example", origins: []string{"https://gööd.example"}},
			allowed: false,
		},
		{
			name:    "origin in CORS allowed origins is accepted",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"https://good.example"}},
			req:     request{host: "gw.example", origins: []string{"https://good.example"}},
			allowed: true,
		},
		{
			name:    "origin not in CORS allowed origins is refused",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"https://good.example"}},
			req:     request{host: "gw.example", origins: []string{"http://attacker.example"}},
			allowed: false,
		},
		{
			name:    "CORS allowed origins are ignored when CORS is off",
			opts:    WebSocketOriginOptions{CORSEnabled: false, AllowedOrigins: []string{"https://good.example"}},
			req:     request{host: "gw.example", origins: []string{"https://good.example"}},
			allowed: false,
		},
		{
			name:    "CORS star wildcard accepts any origin",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"*"}},
			req:     request{host: "gw.example", origins: []string{"http://attacker.example"}},
			allowed: true,
		},
		{
			// Matches Tyk's HTTP CORS middleware, which answers
			// Access-Control-Allow-Origin: * for an empty list.
			name:    "CORS on with no allowed origins accepts any origin",
			opts:    WebSocketOriginOptions{CORSEnabled: true},
			req:     request{host: "gw.example", origins: []string{"http://attacker.example"}},
			allowed: true,
		},
		{
			name:    "CORS subdomain pattern accepts a matching origin",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"https://*.good.example"}},
			req:     request{host: "gw.example", origins: []string{"https://app.good.example"}},
			allowed: true,
		},
		{
			name:    "CORS subdomain pattern refuses a lookalike origin",
			opts:    WebSocketOriginOptions{CORSEnabled: true, AllowedOrigins: []string{"https://*.good.example"}},
			req:     request{host: "gw.example", origins: []string{"https://good.example.attacker.example"}},
			allowed: false,
		},
		{
			name: "forwarded host from a trusted proxy is the own origin",
			opts: WebSocketOriginOptions{TrustedProxyCIDRs: []string{"10.0.0.0/8"}},
			req: request{
				host: "internal:8080", remoteAddr: "10.1.2.3:5555",
				origins: []string{"https://api.example"},
				headers: map[string]string{"X-Forwarded-Host": "api.example", "X-Forwarded-Proto": "https"},
			},
			allowed: true,
		},
		{
			name: "forwarded host from an untrusted client is ignored",
			opts: WebSocketOriginOptions{TrustedProxyCIDRs: []string{"10.0.0.0/8"}},
			req: request{
				host: "internal:8080", remoteAddr: "192.0.2.10:5555",
				origins: []string{"https://attacker.example"},
				headers: map[string]string{"X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "https"},
			},
			allowed: false,
		},
		{
			name:    "allow any origin accepts another origin",
			opts:    WebSocketOriginOptions{AllowAnyOrigin: true},
			req:     request{host: "gw.example", origins: []string{"http://attacker.example"}},
			allowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker, err := NewWebSocketOriginChecker(tc.opts)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodGet, "http://"+tc.req.host+"/ws", nil)
			r.Host = tc.req.host
			if tc.req.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.req.remoteAddr != "" {
				r.RemoteAddr = tc.req.remoteAddr
			}
			for _, origin := range tc.req.origins {
				r.Header.Add("Origin", origin)
			}
			for name, value := range tc.req.headers {
				r.Header.Set(name, value)
			}

			assert.Equal(t, tc.allowed, checker.Allowed(r))
		})
	}
}

func TestNewWebSocketOriginChecker_RejectsInvalidTrustedProxyCIDRs(t *testing.T) {
	_, err := NewWebSocketOriginChecker(WebSocketOriginOptions{TrustedProxyCIDRs: []string{"not-a-cidr"}})
	assert.Error(t, err)
}
