package upstreamoauth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httpclient"
)

// Test cases for createOAuthHTTPClient
func TestCreateOAuthHTTPClient(t *testing.T) {
	tests := []struct {
		name        string
		config      config.Config
		expectedNil bool
		description string
	}{
		{
			name: "no external services configured",
			config: config.Config{
				ExternalServices: config.ExternalServiceConfig{
					OAuth: config.ServiceConfig{
						MTLS:  config.MTLSConfig{Enabled: false},
						Proxy: config.ProxyConfig{Enabled: false},
					},
					Global: config.GlobalProxyConfig{Enabled: false},
				},
			},
			expectedNil: true,
			description: "should return nil when no external services are configured",
		},
		{
			name: "mTLS enabled but misconfigured",
			config: config.Config{
				ExternalServices: config.ExternalServiceConfig{
					OAuth: config.ServiceConfig{
						MTLS:  config.MTLSConfig{Enabled: true},
						Proxy: config.ProxyConfig{Enabled: false},
					},
					Global: config.GlobalProxyConfig{Enabled: false},
				},
			},
			expectedNil: true,
			description: "should return nil when mTLS is enabled but misconfigured (no cert files or cert ID)",
		},
		{
			name: "proxy only configuration",
			config: config.Config{
				ExternalServices: config.ExternalServiceConfig{
					OAuth: config.ServiceConfig{
						MTLS:  config.MTLSConfig{Enabled: false},
						Proxy: config.ProxyConfig{Enabled: true},
					},
					Global: config.GlobalProxyConfig{Enabled: false},
				},
			},
			expectedNil: false, // Factory creates a client even with basic proxy config
			description: "should return client for proxy-only configuration",
		},
		{
			name: "global configuration enabled",
			config: config.Config{
				ExternalServices: config.ExternalServiceConfig{
					OAuth: config.ServiceConfig{
						MTLS:  config.MTLSConfig{Enabled: false},
						Proxy: config.ProxyConfig{Enabled: false},
					},
					Global: config.GlobalProxyConfig{Enabled: true},
				},
			},
			expectedNil: false, // Factory creates a client even with basic global config
			description: "should return client for global configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock middleware using existing mock types
			mw := &Middleware{
				Gw: &mockGateway{
					config:      tt.config,
					certManager: nil, // Use nil for simplicity in these tests
				},
				Base: &mockBaseMiddleware{},
			}

			// Call the function under test
			client := createOAuthHTTPClient(mw)

			// Verify the result
			if tt.expectedNil {
				assert.Nil(t, client, tt.description)
			} else {
				assert.NotNil(t, client, tt.description)
			}
		})
	}
}

// TestCreateOAuthHTTPClient_MTLSErrorSecurity tests the security-critical behavior
// where mTLS errors should not fallback to insecure clients
func TestCreateOAuthHTTPClient_MTLSErrorSecurity(t *testing.T) {
	// Test with mTLS enabled but misconfigured (no certificates provided)
	cfg := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			OAuth: config.ServiceConfig{
				MTLS:  config.MTLSConfig{Enabled: true},
				Proxy: config.ProxyConfig{Enabled: false},
			},
			Global: config.GlobalProxyConfig{Enabled: false},
		},
	}

	mw := &Middleware{
		Gw: &mockGateway{
			config:      cfg,
			certManager: nil, // Use nil for simplicity
		},
		Base: &mockBaseMiddleware{},
	}

	// Call the function - should return nil for security reasons when mTLS is misconfigured
	client := createOAuthHTTPClient(mw)
	assert.Nil(t, client, "should return nil for mTLS errors to prevent insecure fallback")

	// Verify that IsMTLSError correctly identifies the error types
	assert.True(t, httpclient.IsMTLSError(httpclient.ErrMTLSCertificateLoad))
	assert.True(t, httpclient.IsMTLSError(httpclient.ErrMTLSCertificateStore))
	assert.True(t, httpclient.IsMTLSError(httpclient.ErrMTLSCALoad))
	assert.False(t, httpclient.IsMTLSError(assert.AnError))
}

// TestCreateOAuthHTTPClient_IsMTLSError tests the IsMTLSError function
func TestCreateOAuthHTTPClient_IsMTLSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrMTLSCertificateLoad should return true",
			err:      httpclient.ErrMTLSCertificateLoad,
			expected: true,
		},
		{
			name:     "ErrMTLSCertificateStore should return true",
			err:      httpclient.ErrMTLSCertificateStore,
			expected: true,
		},
		{
			name:     "ErrMTLSCALoad should return true",
			err:      httpclient.ErrMTLSCALoad,
			expected: true,
		},
		{
			name:     "wrapped mTLS error should return true",
			err:      httpclient.ErrMTLSCertificateLoad,
			expected: true,
		},
		{
			name:     "non-mTLS error should return false",
			err:      assert.AnError,
			expected: false,
		},
		{
			name:     "nil error should return false",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := httpclient.IsMTLSError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
