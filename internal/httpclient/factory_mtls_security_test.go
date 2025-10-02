package httpclient

import (
	"fmt"
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

				// Also verify we can use IsMTLSError() for mTLS-related errors
				if tt.name != "mTLS enabled with certificate store ID but no cert manager should fail" {
					assert.True(t, IsMTLSError(err))
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

	// Verify we can use IsMTLSError() to check for mTLS certificate loading errors
	assert.True(t, IsMTLSError(err))
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

// TestExternalHTTPClientFactory_CreateWebhookClient tests webhook client creation
func TestExternalHTTPClientFactory_CreateWebhookClient(t *testing.T) {
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "webhook client with proxy configuration should succeed",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true, // Enable proxy to make service configured
				},
				MTLS: config.MTLSConfig{
					Enabled: false, // Disabled to avoid certificate errors in test
				},
			},
			expectError: false,
		},
		{
			name: "webhook client with invalid mTLS should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError:   true,
			errorContains: "failed to configure TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{
				config: &config.ExternalServiceConfig{
					Webhooks: tt.serviceConfig,
				},
				certManager: nil,
			}

			client, err := factory.CreateWebhookClient()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, client)
				assert.True(t, IsMTLSError(err))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &http.Client{}, client)
			}
		})
	}
}

// TestExternalHTTPClientFactory_CreateHealthCheckClient tests health check client creation
func TestExternalHTTPClientFactory_CreateHealthCheckClient(t *testing.T) {
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "health check client with proxy config should succeed",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true, // Enable proxy to make service configured
				},
				MTLS: config.MTLSConfig{
					Enabled: false, // Disabled to avoid certificate errors in test
				},
			},
			expectError: false,
		},
		{
			name: "health check client with invalid mTLS should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError:   true,
			errorContains: "failed to configure TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{
				config: &config.ExternalServiceConfig{
					Health: tt.serviceConfig,
				},
				certManager: nil,
			}

			client, err := factory.CreateHealthCheckClient()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, client)
				assert.True(t, IsMTLSError(err))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &http.Client{}, client)
			}
		})
	}
}

// TestExternalHTTPClientFactory_CreateIntrospectionClient tests introspection client creation
func TestExternalHTTPClientFactory_CreateIntrospectionClient(t *testing.T) {
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "introspection client with proxy config should succeed",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true, // Enable proxy to make service configured
				},
				MTLS: config.MTLSConfig{
					Enabled: false, // Disabled to avoid certificate errors in test
				},
			},
			expectError: false,
		},
		{
			name: "introspection client with invalid mTLS should fail",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError:   true,
			errorContains: "failed to configure TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{
				config: &config.ExternalServiceConfig{
					OAuth: tt.serviceConfig, // Introspection uses OAuth config
				},
				certManager: nil,
			}

			client, err := factory.CreateIntrospectionClient()

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, client)
				assert.True(t, IsMTLSError(err))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &http.Client{}, client)
			}
		})
	}
}

// TestIsMTLSError tests the IsMTLSError function
func TestIsMTLSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrMTLSCertificateLoad should return true",
			err:      ErrMTLSCertificateLoad,
			expected: true,
		},
		{
			name:     "ErrMTLSCertificateStore should return true",
			err:      ErrMTLSCertificateStore,
			expected: true,
		},
		{
			name:     "ErrMTLSCALoad should return true",
			err:      ErrMTLSCALoad,
			expected: true,
		},
		{
			name:     "wrapped ErrMTLSCertificateLoad should return true",
			err:      fmt.Errorf("wrapped error: %w", ErrMTLSCertificateLoad),
			expected: true,
		},
		{
			name:     "other error should return false",
			err:      fmt.Errorf("some other error"),
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
			result := IsMTLSError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
