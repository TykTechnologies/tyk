package httpclient

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

// TestExternalHTTPClientFactory_MTLSSecurityValidation tests that when mTLS is enabled
// but certificate files don't exist, the factory returns an error instead of falling back
// to a default HTTP client, which would bypass the required mutual TLS authentication.
func TestExternalHTTPClientFactory_MTLSSecurityValidation(t *testing.T) {
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "mTLS enabled with non-existent certificate files should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/path/client.crt",
					KeyFile:  "/nonexistent/path/client.key",
				},
			},
			expectError:   true,
			errorContains: "mTLS certificate loading failed",
		},
		{
			name: "mTLS enabled with non-existent CA file should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CAFile:  "/nonexistent/path/ca.crt",
				},
			},
			expectError:   true,
			errorContains: "mTLS CA certificate loading failed",
		},
		{
			name: "mTLS disabled should not fail",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true, // Need some configuration to make service "configured"
				},
				MTLS: config.MTLSConfig{
					Enabled: false,
				},
			},
			expectError: false,
		},
		{
			name: "mTLS enabled with certificate store ID but no cert manager should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "test-cert-id",
				},
			},
			expectError:   true,
			errorContains: "certificate manager not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{
				config: &config.ExternalServiceConfig{
					OAuth: tt.serviceConfig,
				},
				certManager: nil, // No certificate manager for testing
			}

			client, err := factory.CreateOAuthClient()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, client)

				// Also verify we can use errors.Is() for mTLS-related errors
				if tt.name != "mTLS enabled with certificate store ID but no cert manager should fail" {
					assert.True(t, errors.Is(err, ErrMTLSCertificateLoad) || errors.Is(err, ErrMTLSCALoad) || errors.Is(err, ErrMTLSCertificateStore))
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &http.Client{}, client)
			}
		})
	}
}

// TestExternalHTTPClientFactory_MTLSFallbackSecurity tests that when mTLS configuration
// fails, the system does not silently fall back to an insecure default client.
func TestExternalHTTPClientFactory_MTLSFallbackSecurity(t *testing.T) {
	factory := &ExternalHTTPClientFactory{
		config: &config.ExternalServiceConfig{
			OAuth: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		},
		certManager: nil,
	}

	// Attempt to create OAuth client with invalid mTLS configuration
	client, err := factory.CreateOAuthClient()

	// Should fail with error, not return a working client
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to configure TLS")

	// Verify we can use errors.Is() to check for mTLS certificate loading errors
	assert.True(t, errors.Is(err, ErrMTLSCertificateLoad))
}

// TestExternalHTTPClientFactory_ProxyOnlyConfiguration tests that proxy-only
// configuration (without mTLS) works correctly and doesn't fail.
func TestExternalHTTPClientFactory_ProxyOnlyConfiguration(t *testing.T) {
	factory := &ExternalHTTPClientFactory{
		config: &config.ExternalServiceConfig{
			OAuth: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled:    true,
					HTTPProxy:  "http://proxy.example.com:8080",
					HTTPSProxy: "https://proxy.example.com:8080",
				},
			},
		},
		certManager: nil,
	}

	// Should succeed for proxy-only configuration
	client, err := factory.CreateOAuthClient()

	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.IsType(t, &http.Client{}, client)
}
