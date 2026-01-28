package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
)

func TestExternalHTTPClientFactory_CreateClient(t *testing.T) {
	// Test failure case separately
	t.Run("no configuration", func(t *testing.T) {
		factory := &ExternalHTTPClientFactory{
			config: &config.ExternalServiceConfig{},
		}

		client, err := factory.CreateClient(config.ServiceTypeOAuth)
		require.Error(t, err)
		require.Nil(t, client)
		assert.Contains(t, err.Error(), "external services not configured for service type: oauth")
	})

	tests := []struct {
		name        string
		config      config.ExternalServiceConfig
		serviceType string
		wantProxy   bool
		wantMTLS    bool
	}{
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
			// Add certificate manager if mTLS is enabled with certificate store
			var certManager CertificateManager
			if tt.wantMTLS && tt.config.OAuth.MTLS.CertID != "" {
				certManager = &mockCertificateManager{
					certificates: map[string]*tls.Certificate{
						"test-cert-123": createMockCertificate(),
					},
				}
			}

			factory := NewExternalHTTPClientFactory(&tt.config, certManager)
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

func TestExternalHTTPClientFactory_CreateOAuthClient(t *testing.T) {
	serviceConfig := &config.ExternalServiceConfig{
		Global: config.GlobalProxyConfig{
			Enabled: true,
		},
	}

	factory := NewExternalHTTPClientFactory(serviceConfig, nil)
	client, err := factory.CreateOAuthClient()

	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, 15*time.Second, client.Timeout) // OAuth-specific timeout
}

func TestExternalHTTPClientFactory_CreateJWKClient(t *testing.T) {
	t.Run("fails when external services not configured", func(t *testing.T) {
		factory := NewExternalHTTPClientFactory(&config.ExternalServiceConfig{}, nil)

		client, err := factory.CreateJWKClient()
		require.Error(t, err)
		require.Nil(t, client)
		assert.Contains(t, err.Error(), "external services not configured for service type: oauth")
	})

	t.Run("succeeds with OAuth configuration", func(t *testing.T) {
		factory := NewExternalHTTPClientFactory(&config.ExternalServiceConfig{
			OAuth: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					Enabled: true,
				},
			},
		}, nil)

		client, err := factory.CreateJWKClient()
		require.NoError(t, err)
		require.NotNil(t, client)
	})
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

func TestGetJWKWithClient(t *testing.T) {
	// Mock parser function
	parseJWK := func(_ []byte) (*jose.JSONWebKeySet, error) {
		// Simplified mock implementation
		return &jose.JSONWebKeySet{}, nil
	}

	t.Run("successful request", func(t *testing.T) {
		// Create a test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"keys": []}`))
		}))
		defer server.Close()

		client := &http.Client{}
		jwkSet, err := GetJWKWithClient(server.URL, client, parseJWK)

		assert.NoError(t, err)
		assert.NotNil(t, jwkSet)
	})

	t.Run("failed request", func(t *testing.T) {
		client := &http.Client{}
		jwkSet, err := GetJWKWithClient("http://invalid-url", client, parseJWK)

		assert.Error(t, err)
		assert.Nil(t, jwkSet)
	})
}

func TestExternalHTTPClientFactory_CertificateStore(t *testing.T) {
	tests := []struct {
		name          string
		serviceConfig config.ServiceConfig
		setupMocks    func() CertificateManager
		expectError   bool
		errorContains string
	}{
		{
			name: "certificate store - successful certificate load",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "cert123",
				},
			},
			setupMocks: func() CertificateManager {
				return &mockCertificateManager{
					certificates: map[string]*tls.Certificate{
						"cert123": createMockCertificate(),
					},
				}
			},
			expectError: false,
		},
		{
			name: "certificate store - certificate not found",
			serviceConfig: config.ServiceConfig{
				MTLS: config.MTLSConfig{
					Enabled: true,
					CertID:  "nonexistent",
				},
			},
			setupMocks: func() CertificateManager {
				return &mockCertificateManager{
					certificates: map[string]*tls.Certificate{},
				}
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
			setupMocks:    func() CertificateManager { return nil },
			expectError:   true,
			errorContains: "certificate manager not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := &ExternalHTTPClientFactory{
				certManager: tt.setupMocks(),
			}

			tlsConfig, err := factory.getTLSConfig(tt.serviceConfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
			}
		})
	}
}

// Mock certificate manager for testing
type mockCertificateManager struct {
	certificates   map[string]*tls.Certificate
	caCertificates []string
}

func (m *mockCertificateManager) List(certIDs []string, _ certs.CertificateType) (out []*tls.Certificate) {
	for _, id := range certIDs {
		if cert, exists := m.certificates[id]; exists {
			out = append(out, cert)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (m *mockCertificateManager) ListPublicKeys(_ []string) (out []string) {
	return []string{}
}

func (m *mockCertificateManager) ListRawPublicKey(_ string) interface{} {
	return nil
}

func (m *mockCertificateManager) ListAllIds(_ string) []string {
	var ids []string
	for id := range m.certificates {
		ids = append(ids, id)
	}
	return ids
}

func (m *mockCertificateManager) GetRaw(_ string) (string, error) {
	return "", nil
}

func (m *mockCertificateManager) Add(_ []byte, _ string) (string, error) {
	return "", nil
}

func (m *mockCertificateManager) Delete(_ string, _ string) {}

func (m *mockCertificateManager) CertPool(certIDs []string) *x509.CertPool {
	if len(certIDs) == 0 {
		return nil
	}

	if len(m.caCertificates) > 0 {
		pool := x509.NewCertPool()
		return pool
	}

	return nil
}

func (m *mockCertificateManager) FlushCache() {}

func (m *mockCertificateManager) SetRegistry(_ certs.CertRegistry) {}

// Helper function to create a mock certificate for testing
func createMockCertificate() *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{[]byte("mock cert data")},
	}
}
