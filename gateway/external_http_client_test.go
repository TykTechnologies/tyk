package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
)

func TestExternalHTTPClientFactory_CreateClient(t *testing.T) {
	tests := []struct {
		name        string
		config      config.ExternalServiceConfig
		serviceType string
		wantProxy   bool
		wantMTLS    bool
	}{
		{
			name:        "no configuration",
			config:      config.ExternalServiceConfig{},
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   false,
			wantMTLS:    false,
		},
		{
			name: "global proxy configuration",
			config: config.ExternalServiceConfig{
				Global: config.GlobalProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://proxy:8080",
				},
			},
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   true,
			wantMTLS:    false,
		},
		{
			name: "service-specific proxy overrides global",
			config: config.ExternalServiceConfig{
				Global: config.GlobalProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://global-proxy:8080",
				},
				OAuth: config.ServiceConfig{
					Proxy: config.ProxyConfig{
						Enabled:   true,
						HTTPProxy: "http://oauth-proxy:8080",
					},
				},
			},
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   true,
			wantMTLS:    false,
		},
		{
			name: "environment proxy configuration",
			config: config.ExternalServiceConfig{
				Global: config.GlobalProxyConfig{
					Enabled: true,
				},
			},
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   true,
			wantMTLS:    false,
		},
		{
			name: "mTLS configuration",
			config: config.ExternalServiceConfig{
				OAuth: config.ServiceConfig{
					MTLS: config.MTLSConfig{
						Enabled:            true,
						CertID:             "test-cert-123",
						InsecureSkipVerify: true,
					},
				},
			},
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   false,
			wantMTLS:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock gateway config
			gwConfig := config.Config{
				ExternalServices: tt.config,
			}

			// Create a mock gateway
			gw := &Gateway{}
			gw.SetConfig(gwConfig)

			// Add certificate manager if mTLS is enabled with certificate store
			if tt.wantMTLS && tt.config.OAuth.MTLS.CertID != "" {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{
						"test-cert-123": createMockCertificate(),
					},
				}
				gw.CertificateManager = mockCertManager
			}

			factory := NewExternalHTTPClientFactory(gw)
			client, err := factory.CreateClient(tt.serviceType)

			require.NoError(t, err)
			require.NotNil(t, client)

			// Check client configuration - timeout should match service type
			expectedTimeout := 30 * time.Second // Default for most services
			if tt.serviceType == config.ServiceTypeOAuth {
				expectedTimeout = 15 * time.Second
			} else if tt.serviceType == config.ServiceTypeHealth || tt.serviceType == config.ServiceTypeDiscovery {
				expectedTimeout = 10 * time.Second
			}
			assert.Equal(t, expectedTimeout, client.Timeout)

			transport := client.Transport.(*http.Transport)
			assert.NotNil(t, transport)

			if tt.wantProxy {
				assert.NotNil(t, transport.Proxy)
			}

			if tt.wantMTLS {
				assert.NotNil(t, transport.TLSClientConfig)
				assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
			}
		})
	}
}

func TestExternalHTTPClientFactory_getServiceConfig(t *testing.T) {
	factory := &ExternalHTTPClientFactory{
		config: &config.ExternalServiceConfig{
			Global: config.GlobalProxyConfig{
				Enabled:   true,
				HTTPProxy: "http://global-proxy:8080",
			},
			OAuth: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://oauth-proxy:8080",
				},
			},
		},
	}

	tests := []struct {
		name        string
		serviceType string
		wantProxy   string
	}{
		{
			name:        "OAuth service gets specific config",
			serviceType: config.ServiceTypeOAuth,
			wantProxy:   "http://oauth-proxy:8080",
		},
		{
			name:        "Unknown service gets global config",
			serviceType: "unknown",
			wantProxy:   "http://global-proxy:8080",
		},
		{
			name:        "Storage service gets global config",
			serviceType: config.ServiceTypeStorage,
			wantProxy:   "http://global-proxy:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceConfig := factory.getServiceConfig(tt.serviceType)

			if tt.wantProxy != "" {
				if strings.HasPrefix(tt.wantProxy, "https://") {
					assert.Equal(t, tt.wantProxy, serviceConfig.Proxy.HTTPSProxy)
				} else {
					assert.Equal(t, tt.wantProxy, serviceConfig.Proxy.HTTPProxy)
				}
			}
		})
	}
}

func TestExternalHTTPClientFactory_getProxyFunction(t *testing.T) {
	factory := &ExternalHTTPClientFactory{}

	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		wantProxy     bool
		wantEnv       bool
	}{
		{
			name:          "no proxy config",
			serviceConfig: config.ServiceConfig{},
			wantProxy:     false,
			wantEnv:       false,
		},
		{
			name: "HTTP proxy configured",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://proxy:8080",
				},
			},
			wantProxy: true,
			wantEnv:   false,
		},
		{
			name: "environment proxy",
			serviceConfig: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true,
				},
			},
			wantProxy: true,
			wantEnv:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyFunc, err := factory.getProxyFunction(tt.serviceConfig)
			require.NoError(t, err)

			if tt.wantProxy {
				assert.NotNil(t, proxyFunc)

				if tt.wantEnv {
					// For environment proxy, we can't easily test the exact function,
					// but we can check it's not nil
					assert.NotNil(t, proxyFunc)
				} else {
					// Test custom proxy function
					req, _ := http.NewRequest("GET", "http://example.com", nil)
					proxyURL, err := proxyFunc(req)
					require.NoError(t, err)
					if tt.serviceConfig.Proxy.HTTPProxy != "" {
						assert.NotNil(t, proxyURL)
						assert.Equal(t, "proxy:8080", proxyURL.Host)
					}
				}
			} else {
				assert.Nil(t, proxyFunc)
			}
		})
	}
}

func TestSplitBypassProxy(t *testing.T) {
	tests := []struct {
		name    string
		noProxy string
		want    []string
	}{
		{
			name:    "empty string",
			noProxy: "",
			want:    nil,
		},
		{
			name:    "single host",
			noProxy: "localhost",
			want:    []string{"localhost"},
		},
		{
			name:    "multiple hosts",
			noProxy: "localhost,127.0.0.1,example.com",
			want:    []string{"localhost", "127.0.0.1", "example.com"},
		},
		{
			name:    "hosts with spaces",
			noProxy: "localhost, 127.0.0.1 , example.com",
			want:    []string{"localhost", "127.0.0.1", "example.com"},
		},
		{
			name:    "hosts with empty entries",
			noProxy: "localhost,,example.com",
			want:    []string{"localhost", "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitBypassProxy(tt.noProxy)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExternalHTTPClientFactory_shouldBypassProxy(t *testing.T) {
	factory := &ExternalHTTPClientFactory{}

	tests := []struct {
		name    string
		host    string
		noProxy string
		want    bool
	}{
		{
			name:    "empty no proxy",
			host:    "example.com",
			noProxy: "",
			want:    false,
		},
		{
			name:    "exact match",
			host:    "example.com",
			noProxy: "example.com",
			want:    true,
		},
		{
			name:    "no match",
			host:    "example.com",
			noProxy: "other.com",
			want:    false,
		},
		{
			name:    "localhost special case",
			host:    "127.0.0.1",
			noProxy: "localhost",
			want:    true,
		},
		{
			name:    "localhost exact match",
			host:    "localhost",
			noProxy: "localhost",
			want:    true,
		},
		{
			name:    "multiple hosts - match",
			host:    "example.com",
			noProxy: "localhost,example.com,other.com",
			want:    true,
		},
		{
			name:    "multiple hosts - no match",
			host:    "nomatch.com",
			noProxy: "localhost,example.com,other.com",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factory.shouldBypassProxy(tt.host, tt.noProxy)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExternalHTTPClientFactory_CreateJWKClient(t *testing.T) {
	t.Run("legacy behavior when external services not configured", func(t *testing.T) {
		gwConfig := config.Config{
			ExternalServices: config.ExternalServiceConfig{
				Global: config.GlobalProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://proxy:8080",
				},
			},
		}

		gw := &Gateway{}
		gw.SetConfig(gwConfig)
		factory := NewExternalHTTPClientFactory(gw)

		// Legacy setting should be used when external services OAuth mTLS is not configured
		client, err := factory.CreateJWKClient(true)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify) // Should use legacy setting
		assert.NotNil(t, transport.Proxy)                            // Should have proxy from config
	})

	t.Run("external services takes precedence when configured", func(t *testing.T) {
		gwConfig := config.Config{
			ExternalServices: config.ExternalServiceConfig{
				Global: config.GlobalProxyConfig{
					Enabled:   true,
					HTTPProxy: "http://proxy:8080",
				},
				OAuth: config.ServiceConfig{
					MTLS: config.MTLSConfig{
						InsecureSkipVerify: false, // External services says false
					},
				},
			},
		}

		gw := &Gateway{}
		gw.SetConfig(gwConfig)
		factory := NewExternalHTTPClientFactory(gw)

		// External services setting should override legacy setting
		client, err := factory.CreateJWKClient(true) // Legacy says true
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify) // Should use external services setting (false)
		assert.NotNil(t, transport.Proxy)                             // Should have proxy from config
	})

	t.Run("legacy fallback when only enabled=true but no other mTLS config", func(t *testing.T) {
		gwConfig := config.Config{
			ExternalServices: config.ExternalServiceConfig{
				OAuth: config.ServiceConfig{
					MTLS: config.MTLSConfig{
						Enabled: true, // Only enabled is set, no other mTLS configuration
					},
				},
			},
		}

		gw := &Gateway{}
		gw.SetConfig(gwConfig)
		factory := NewExternalHTTPClientFactory(gw)

		// Should use legacy since enabled=true alone is not considered explicit configuration
		client, err := factory.CreateJWKClient(true) // Legacy says true
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify) // Should use legacy setting (true)
	})
}

func TestExternalHTTPClientFactory_SpecializedClients(t *testing.T) {
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Global: config.GlobalProxyConfig{
				Enabled:   true,
				HTTPProxy: "http://proxy:8080",
			},
		},
	}

	gw := &Gateway{}
	gw.SetConfig(gwConfig)

	factory := NewExternalHTTPClientFactory(gw)

	t.Run("CreateIntrospectionClient", func(t *testing.T) {
		client, err := factory.CreateIntrospectionClient()
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.NotNil(t, transport.Proxy)
	})

	t.Run("CreateWebhookClient", func(t *testing.T) {
		client, err := factory.CreateWebhookClient()
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.NotNil(t, transport.Proxy)
	})

}

// Test mTLS configuration with temporary certificates
func TestExternalHTTPClientFactory_MTLSConfig(t *testing.T) {
	// Skip this test if we can't create temporary files
	if testing.Short() {
		t.Skip("Skipping mTLS test in short mode")
	}

	// Create temporary certificate files for testing
	certPEM := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCWl8gJP4dw7jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMzEyMjcyMzU5NTlaFw0yNDEyMjYyMzU5NTlaMHUxCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYkYcKFNlZz6Zv
-----END PRIVATE KEY-----`

	caPEM := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCWl8gJP4dw7jANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----`

	// Create temporary files
	certFile, err := ioutil.TempFile("", "cert_*.pem")
	require.NoError(t, err)
	defer os.Remove(certFile.Name())
	defer certFile.Close()

	keyFile, err := ioutil.TempFile("", "key_*.pem")
	require.NoError(t, err)
	defer os.Remove(keyFile.Name())
	defer keyFile.Close()

	caFile, err := ioutil.TempFile("", "ca_*.pem")
	require.NoError(t, err)
	defer os.Remove(caFile.Name())
	defer caFile.Close()

	// Write test certificates
	_, err = certFile.WriteString(certPEM)
	require.NoError(t, err)
	certFile.Close()

	_, err = keyFile.WriteString(keyPEM)
	require.NoError(t, err)
	keyFile.Close()

	_, err = caFile.WriteString(caPEM)
	require.NoError(t, err)
	caFile.Close()

	// Test with invalid certificates (expected to fail)
	factory := &ExternalHTTPClientFactory{}
	serviceConfig := config.ServiceConfig{
		MTLS: config.MTLSConfig{
			Enabled:  true,
			CertFile: certFile.Name(),
			KeyFile:  keyFile.Name(),
			CAFile:   caFile.Name(),
		},
	}

	// This should fail with invalid certificates, but we test the configuration logic
	_, err = factory.getTLSConfig(serviceConfig)
	// We expect an error with the dummy certificates
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestExternalHTTPClientFactory_createCustomProxyFunc(t *testing.T) {
	factory := &ExternalHTTPClientFactory{}

	proxyConfig := config.ProxyConfig{
		HTTPProxy:   "http://http-proxy:8080",
		HTTPSProxy:  "https://https-proxy:8080",
		BypassProxy: "localhost,127.0.0.1",
	}

	proxyFunc := factory.createCustomProxyFunc(proxyConfig)

	t.Run("HTTP request uses HTTP proxy", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		proxyURL, err := proxyFunc(req)
		require.NoError(t, err)
		require.NotNil(t, proxyURL)
		assert.Equal(t, "http-proxy:8080", proxyURL.Host)
	})

	t.Run("HTTPS request uses HTTPS proxy", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		proxyURL, err := proxyFunc(req)
		require.NoError(t, err)
		require.NotNil(t, proxyURL)
		assert.Equal(t, "https-proxy:8080", proxyURL.Host)
	})

	t.Run("localhost bypasses proxy", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://localhost/test", nil)
		proxyURL, err := proxyFunc(req)
		require.NoError(t, err)
		assert.Nil(t, proxyURL)
	})

	t.Run("127.0.0.1 bypasses proxy", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1/test", nil)
		proxyURL, err := proxyFunc(req)
		require.NoError(t, err)
		assert.Nil(t, proxyURL)
	})
}

func TestExternalHTTPClientFactory_getServiceTransport(t *testing.T) {
	factory := &ExternalHTTPClientFactory{}

	tests := []struct {
		name                        string
		serviceType                 string
		expectedMaxIdleConns        int
		expectedMaxIdleConnsPerHost int
		expectedIdleConnTimeout     time.Duration
	}{
		{
			name:                        "OAuth service",
			serviceType:                 config.ServiceTypeOAuth,
			expectedMaxIdleConns:        50,
			expectedMaxIdleConnsPerHost: 10,
			expectedIdleConnTimeout:     30 * time.Second,
		},
		{
			name:                        "Webhook service",
			serviceType:                 config.ServiceTypeWebhook,
			expectedMaxIdleConns:        50,
			expectedMaxIdleConnsPerHost: 10,
			expectedIdleConnTimeout:     30 * time.Second,
		},
		{
			name:                        "Health service",
			serviceType:                 config.ServiceTypeHealth,
			expectedMaxIdleConns:        20,
			expectedMaxIdleConnsPerHost: 5,
			expectedIdleConnTimeout:     15 * time.Second,
		},
		{
			name:                        "Discovery service",
			serviceType:                 config.ServiceTypeDiscovery,
			expectedMaxIdleConns:        30,
			expectedMaxIdleConnsPerHost: 5,
			expectedIdleConnTimeout:     20 * time.Second,
		},
		{
			name:                        "Storage service",
			serviceType:                 config.ServiceTypeStorage,
			expectedMaxIdleConns:        50,
			expectedMaxIdleConnsPerHost: 15,
			expectedIdleConnTimeout:     90 * time.Second,
		},
		{
			name:                        "Unknown service (default)",
			serviceType:                 "unknown",
			expectedMaxIdleConns:        100,
			expectedMaxIdleConnsPerHost: 10,
			expectedIdleConnTimeout:     30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := factory.getServiceTransport(tt.serviceType)
			assert.NotNil(t, transport)
			assert.Equal(t, tt.expectedMaxIdleConns, transport.MaxIdleConns)
			assert.Equal(t, tt.expectedMaxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
			assert.Equal(t, tt.expectedIdleConnTimeout, transport.IdleConnTimeout)
		})
	}
}

func TestExternalHTTPClientFactory_getTLSConfig(t *testing.T) {
	factory := &ExternalHTTPClientFactory{}

	invalidCertData := "invalid certificate data"

	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		setupFiles    func(t *testing.T) (certFile, keyFile, caFile string)
		expectError   bool
		errorContains string
		validateTLS   func(t *testing.T, tlsConfig *tls.Config)
	}{
		{
			name: "basic TLS config with InsecureSkipVerify false",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:            false,
					InsecureSkipVerify: false,
				},
			},
			expectError: false,
			validateTLS: func(t *testing.T, tlsConfig *tls.Config) {
				assert.False(t, tlsConfig.InsecureSkipVerify)
				assert.Nil(t, tlsConfig.Certificates)
				assert.Nil(t, tlsConfig.RootCAs)
			},
		},
		{
			name: "basic TLS config with InsecureSkipVerify true",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:            false,
					InsecureSkipVerify: true,
				},
			},
			expectError: false,
			validateTLS: func(t *testing.T, tlsConfig *tls.Config) {
				assert.True(t, tlsConfig.InsecureSkipVerify)
				assert.Nil(t, tlsConfig.Certificates)
				assert.Nil(t, tlsConfig.RootCAs)
			},
		},
		{
			name: "mTLS enabled but no cert/key files",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "",
					KeyFile:  "",
					CAFile:   "",
				},
			},
			expectError:   true,
			errorContains: "mTLS enabled but no certificate configuration provided",
		},
		{
			name: "mTLS enabled with invalid cert file",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			expectError:   true,
			errorContains: "failed to load client certificate",
		},
		{
			name: "mTLS enabled with invalid CA file path",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CAFile:  "/nonexistent/ca.pem",
				},
			},
			expectError:   true,
			errorContains: "failed to read CA certificate",
		},
		{
			name: "mTLS enabled with invalid CA content",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
				},
			},
			setupFiles: func(t *testing.T) (certFile, keyFile, caFile string) {
				caFileHandle, err := ioutil.TempFile("", "invalid_ca_*.pem")
				require.NoError(t, err)
				_, err = caFileHandle.WriteString(invalidCertData)
				require.NoError(t, err)
				caFileHandle.Close()
				return "", "", caFileHandle.Name()
			},
			expectError:   true,
			errorContains: "failed to parse CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certFile, keyFile, caFile string

			if tt.setupFiles != nil {
				certFile, keyFile, caFile = tt.setupFiles(t)
				if certFile != "" {
					defer os.Remove(certFile)
					tt.serviceConfig.MTLS.CertFile = certFile
				}
				if keyFile != "" {
					defer os.Remove(keyFile)
					tt.serviceConfig.MTLS.KeyFile = keyFile
				}
				if caFile != "" {
					defer os.Remove(caFile)
					tt.serviceConfig.MTLS.CAFile = caFile
				}
			}

			tlsConfig, err := factory.getTLSConfig(tt.serviceConfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, tlsConfig)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				if tt.validateTLS != nil {
					tt.validateTLS(t, tlsConfig)
				}
			}
		})
	}
}

// Mock certificate manager for testing
type mockExternalHTTPClientCertificateManager struct {
	certificates   map[string]*tls.Certificate
	caCertificates []string
}

func (m *mockExternalHTTPClientCertificateManager) List(certIDs []string, _ certs.CertificateType) (out []*tls.Certificate) {
	for _, id := range certIDs {
		if cert, exists := m.certificates[id]; exists {
			out = append(out, cert)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (m *mockExternalHTTPClientCertificateManager) ListPublicKeys(_ []string) (out []string) {
	return []string{}
}

func (m *mockExternalHTTPClientCertificateManager) ListRawPublicKey(_ string) interface{} {
	return nil
}

func (m *mockExternalHTTPClientCertificateManager) ListAllIds(_ string) []string {
	var ids []string
	for id := range m.certificates {
		ids = append(ids, id)
	}
	return ids
}

func (m *mockExternalHTTPClientCertificateManager) GetRaw(_ string) (string, error) {
	return "", nil
}

func (m *mockExternalHTTPClientCertificateManager) Add(_ []byte, _ string) (string, error) {
	return "", nil
}

func (m *mockExternalHTTPClientCertificateManager) Delete(_ string, _ string) {}

func (m *mockExternalHTTPClientCertificateManager) CertPool(certIDs []string) *x509.CertPool {
	if len(certIDs) == 0 {
		return nil
	}

	// Check if we have CA certificates configured for this mock
	if len(m.caCertificates) > 0 {
		pool := x509.NewCertPool()
		// In a real implementation, we'd add actual certificates
		// For testing purposes, just return a non-nil pool
		return pool
	}

	return nil
}

func (m *mockExternalHTTPClientCertificateManager) FlushCache() {}

// Helper function to create a mock certificate for testing
func createMockCertificate() *tls.Certificate {
	// Create a minimal certificate for testing
	// In practice, you'd use real certificate data
	return &tls.Certificate{
		Certificate: [][]byte{[]byte("mock cert data")},
	}
}

func TestExternalHTTPClientFactory_getTLSConfig_CertificateStore(t *testing.T) {
	tests := []struct {
		name              string
		serviceConfig     config.ServiceConfig
		setupMocks        func(*Gateway)
		expectError       bool
		errorContains     string
		validateTLSConfig func(t *testing.T, tlsConfig *tls.Config)
	}{
		{
			name: "certificate store - successful certificate load",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "cert123",
				},
			},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{
						"cert123": createMockCertificate(),
					},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError: false,
			validateTLSConfig: func(t *testing.T, tlsConfig *tls.Config) {
				assert.Len(t, tlsConfig.Certificates, 1)
				assert.False(t, tlsConfig.InsecureSkipVerify)
			},
		},
		{
			name: "certificate store - certificate not found",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "nonexistent",
				},
			},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError:   true,
			errorContains: "certificate not found in store",
		},
		{
			name: "certificate store - no certificate manager",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "cert123",
				},
			},
			setupMocks: func(gw *Gateway) {
				gw.CertificateManager = nil
			},
			expectError:   true,
			errorContains: "certificate manager not available",
		},
		{
			name: "certificate store with CA certificates",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:   true,
					CertID:    "cert123",
					CACertIDs: []string{"ca123", "ca456"},
				},
			},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{
						"cert123": createMockCertificate(),
					},
					caCertificates: []string{"ca123", "ca456"},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError: false,
			validateTLSConfig: func(t *testing.T, tlsConfig *tls.Config) {
				assert.Len(t, tlsConfig.Certificates, 1)
				assert.NotNil(t, tlsConfig.RootCAs)
			},
		},
		{
			name: "certificate store - invalid configuration mixed with files",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertID:   "cert123",
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			setupMocks:    func(_ *Gateway) {},
			expectError:   true,
			errorContains: "cannot specify both file-based and certificate store configuration",
		},
		{
			name: "certificate store - insecure skip verify",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:            true,
					CertID:             "cert123",
					InsecureSkipVerify: true,
				},
			},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{
						"cert123": createMockCertificate(),
					},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError: false,
			validateTLSConfig: func(t *testing.T, tlsConfig *tls.Config) {
				assert.Len(t, tlsConfig.Certificates, 1)
				assert.True(t, tlsConfig.InsecureSkipVerify)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test gateway
			gw := &Gateway{}
			tt.setupMocks(gw)

			factory := &ExternalHTTPClientFactory{gw: gw}

			tlsConfig, err := factory.getTLSConfig(tt.serviceConfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				if tt.validateTLSConfig != nil {
					tt.validateTLSConfig(t, tlsConfig)
				}
			}
		})
	}
}

func TestExternalHTTPClientFactory_loadCertificateFromStore(t *testing.T) {
	tests := []struct {
		name          string
		certID        string
		setupMocks    func(*Gateway)
		expectError   bool
		errorContains string
	}{
		{
			name:   "successful certificate load",
			certID: "cert123",
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{
						"cert123": createMockCertificate(),
					},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError: false,
		},
		{
			name:   "certificate not found",
			certID: "nonexistent",
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					certificates: map[string]*tls.Certificate{},
				}
				gw.CertificateManager = mockCertManager
			},
			expectError:   true,
			errorContains: "certificate not found in store",
		},
		{
			name:   "certificate manager not available",
			certID: "cert123",
			setupMocks: func(gw *Gateway) {
				gw.CertificateManager = nil
			},
			expectError:   true,
			errorContains: "certificate manager not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &Gateway{}
			tt.setupMocks(gw)

			factory := &ExternalHTTPClientFactory{gw: gw}
			cert, err := factory.loadCertificateFromStore(tt.certID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

func TestExternalHTTPClientFactory_loadCACertPoolFromStore(t *testing.T) {
	tests := []struct {
		name       string
		certIDs    []string
		setupMocks func(*Gateway)
		expectNil  bool
	}{
		{
			name:    "successful CA cert pool creation",
			certIDs: []string{"ca123", "ca456"},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{
					caCertificates: []string{"ca123", "ca456"},
				}
				gw.CertificateManager = mockCertManager
			},
			expectNil: false,
		},
		{
			name:    "empty cert IDs",
			certIDs: []string{},
			setupMocks: func(gw *Gateway) {
				mockCertManager := &mockExternalHTTPClientCertificateManager{}
				gw.CertificateManager = mockCertManager
			},
			expectNil: true,
		},
		{
			name:    "certificate manager not available",
			certIDs: []string{"ca123"},
			setupMocks: func(gw *Gateway) {
				gw.CertificateManager = nil
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &Gateway{}
			tt.setupMocks(gw)

			factory := &ExternalHTTPClientFactory{gw: gw}
			certPool := factory.loadCACertPoolFromStore(tt.certIDs)

			if tt.expectNil {
				assert.Nil(t, certPool)
			} else {
				assert.NotNil(t, certPool)
			}
		})
	}
}

func TestExternalHTTPClientFactory_BackwardCompatibility(t *testing.T) {
	// Ensure that existing file-based configurations continue to work
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		expectError   bool
		description   string
	}{
		{
			name: "file-based configuration still works",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  false, // Disabled should not cause issues
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expectError: false,
			description: "Disabled mTLS with file paths should work",
		},
		{
			name: "empty certificate store fields do not interfere",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:   false,
					CertID:    "", // Empty cert ID should not interfere
					CACertIDs: nil,
				},
			},
			expectError: false,
			description: "Empty certificate store fields should not cause issues when mTLS is disabled",
		},
		{
			name: "mixed configuration validation works correctly",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled:  true,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
					CertID:   "cert123", // This should trigger validation error
				},
			},
			expectError: true,
			description: "Mixed configuration should be properly rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{}
			_, err := factory.getTLSConfig(tt.serviceConfig)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestExternalHTTPClientFactory_CertificateStoreIntegration(t *testing.T) {
	// Integration test to verify the complete flow works

	// Create a mock gateway with certificate manager
	gw := &Gateway{}
	mockCertManager := &mockExternalHTTPClientCertificateManager{
		certificates: map[string]*tls.Certificate{
			"client-cert-123": createMockCertificate(),
		},
		caCertificates: []string{"ca-cert-456", "ca-cert-789"},
	}
	gw.CertificateManager = mockCertManager

	// Create the factory
	factory := &ExternalHTTPClientFactory{gw: gw}

	// Test various service configurations
	testConfigs := []struct {
		name        string
		serviceType string
		mtlsConfig  config.MTLSConfig
		expectError bool
	}{
		{
			name:        "OAuth with certificate store",
			serviceType: "oauth",
			mtlsConfig: config.MTLSConfig{
				Enabled:   true,
				CertID:    "client-cert-123",
				CACertIDs: []string{"ca-cert-456", "ca-cert-789"},
			},
			expectError: false,
		},
		{
			name:        "Storage with file-based (backward compatibility)",
			serviceType: "storage",
			mtlsConfig: config.MTLSConfig{
				Enabled: false, // Disabled to avoid file system dependency
			},
			expectError: false,
		},
		{
			name:        "Webhook with certificate store - certificate not found",
			serviceType: "webhook",
			mtlsConfig: config.MTLSConfig{
				Enabled: true,
				CertID:  "nonexistent-cert",
			},
			expectError: true,
		},
	}

	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			serviceConfig := config.ServiceConfig{
				MTLS: tc.mtlsConfig,
			}

			tlsConfig, err := factory.getTLSConfig(serviceConfig)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, tlsConfig)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)

				// Verify TLS configuration properties
				if tc.mtlsConfig.Enabled && tc.mtlsConfig.CertID != "" {
					assert.Len(t, tlsConfig.Certificates, 1, "Should have one client certificate")
				}
				if len(tc.mtlsConfig.CACertIDs) > 0 {
					assert.NotNil(t, tlsConfig.RootCAs, "Should have CA certificate pool")
				}
				assert.Equal(t, tc.mtlsConfig.InsecureSkipVerify, tlsConfig.InsecureSkipVerify)
			}
		})
	}
}
