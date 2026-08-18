package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/middleware"
)

func TestMCPOriginValidationMiddleware(t *testing.T) {
	t.Parallel()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			MCP: &apidef.MCPConfig{TrustedOrigins: []string{
				"https://TRUSTED.example:443",
			}},
		},
		GlobalConfig: config.Config{HttpServerOptions: config.HttpServerOptionsConfig{
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		}},
	}
	mw := &MCPOriginValidationMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}

	tests := []struct {
		name       string
		origin     string
		forwarded  string
		remoteAddr string
		wantStatus int
	}{
		{name: "absent", wantStatus: http.StatusOK},
		{name: "same direct", origin: "http://gateway.example", wantStatus: http.StatusOK},
		{name: "canonical same direct", origin: "HTTP://GATEWAY.EXAMPLE:80", wantStatus: http.StatusOK},
		{name: "explicit trusted", origin: "https://trusted.example", wantStatus: http.StatusOK},
		{name: "same forwarded from trusted peer", origin: "https://public.example", forwarded: "for=192.0.2.1;proto=https;host=public.example", remoteAddr: "10.0.0.2:80", wantStatus: http.StatusOK},
		{name: "spoofed forwarded from untrusted peer", origin: "https://public.example", forwarded: "for=192.0.2.1;proto=https;host=public.example", remoteAddr: "192.0.2.2:80", wantStatus: http.StatusForbidden},
		{name: "untrusted", origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "null", origin: "null", wantStatus: http.StatusForbidden},
		{name: "wildcard", origin: "https://*.example", wantStatus: http.StatusForbidden},
		{name: "malformed", origin: "://bad", wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://gateway.example/mcp", nil)
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			if test.forwarded != "" {
				req.Header.Set("Forwarded", test.forwarded)
			}
			if test.remoteAddr != "" {
				req.RemoteAddr = test.remoteAddr
			}
			rec := httptest.NewRecorder()

			err, status := mw.ProcessRequest(rec, req, nil)
			require.NoError(t, err)
			if test.wantStatus == http.StatusForbidden {
				assert.Equal(t, middleware.StatusRespond, status)
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Equal(t, "Forbidden\n", rec.Body.String())
				assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
				return
			}
			assert.Equal(t, http.StatusOK, status)
			assert.Empty(t, rec.Body.String())
		})
	}
}

func TestMCPOriginValidationPreparesImmutableConfigOnce(t *testing.T) {
	t.Parallel()

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			ApplicationProtocol: apidef.AppProtocolMCP,
			MCP:                 &apidef.MCPConfig{TrustedOrigins: []string{"HTTPS://CLIENT.EXAMPLE:443"}},
		},
		GlobalConfig: config.Config{HttpServerOptions: config.HttpServerOptionsConfig{
			TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		}},
	}
	require.NoError(t, spec.prepareMCPOriginConfig())
	assert.Contains(t, spec.mcpTrustedOrigins, "https://client.example")
	require.Len(t, spec.mcpTrustedProxyPrefixes, 1)

	// Loaded API specs are immutable. Corrupting the source slices after
	// preparation proves subsequent requests use the parsed runtime cache.
	spec.MCP.TrustedOrigins[0] = "null"
	spec.GlobalConfig.HttpServerOptions.TrustedProxyCIDRs[0] = "not-a-cidr"
	require.NoError(t, spec.prepareMCPOriginConfig())

	req := httptest.NewRequest(http.MethodPost, "http://internal.example/mcp", nil)
	req.RemoteAddr = "10.0.0.2:80"
	req.Header.Set("Forwarded", "for=192.0.2.1;proto=https;host=public.example")
	external, err := externalOriginForSpec(req, spec)
	require.NoError(t, err)
	assert.Equal(t, "https://public.example", external)

	mw := &MCPOriginValidationMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	req.Header.Set("Origin", "https://client.example")
	err, status := mw.ProcessRequest(httptest.NewRecorder(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}
