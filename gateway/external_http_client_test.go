package gateway

import (
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				Proxy: config.ProxyConfig{
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
				Proxy: config.ProxyConfig{
					HTTPProxy: "http://global-proxy:8080",
				},
				OAuth: config.ServiceConfig{
					Proxy: config.ProxyConfig{
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
				Proxy: config.ProxyConfig{
					UseEnvironment: true,
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

			factory := NewExternalHTTPClientFactory(gw)
			client, err := factory.CreateClient(tt.serviceType)

			require.NoError(t, err)
			require.NotNil(t, client)

			// Check client configuration
			assert.Equal(t, 30*time.Second, client.Timeout)

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
			Proxy: config.ProxyConfig{
				HTTPProxy: "http://global-proxy:8080",
			},
			OAuth: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					HTTPProxy: "http://oauth-proxy:8080",
				},
			},
			Analytics: config.ServiceConfig{
				Proxy: config.ProxyConfig{
					HTTPSProxy: "https://analytics-proxy:8080",
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
			name:        "Analytics service gets specific config",
			serviceType: config.ServiceTypeAnalytics,
			wantProxy:   "https://analytics-proxy:8080",
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
					UseEnvironment: true,
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

func TestSplitNoProxy(t *testing.T) {
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
			got := splitNoProxy(tt.noProxy)
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
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: "http://proxy:8080",
			},
		},
	}

	gw := &Gateway{}
	gw.SetConfig(gwConfig)

	factory := NewExternalHTTPClientFactory(gw)

	t.Run("with insecure skip verify true", func(t *testing.T) {
		client, err := factory.CreateJWKClient(true)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
		assert.NotNil(t, transport.Proxy) // Should have proxy from config
	})

	t.Run("with insecure skip verify false", func(t *testing.T) {
		client, err := factory.CreateJWKClient(false)
		require.NoError(t, err)
		require.NotNil(t, client)

		transport := client.Transport.(*http.Transport)
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
		assert.NotNil(t, transport.Proxy) // Should have proxy from config
	})
}

func TestExternalHTTPClientFactory_SpecializedClients(t *testing.T) {
	gwConfig := config.Config{
		ExternalServices: config.ExternalServiceConfig{
			Proxy: config.ProxyConfig{
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

	t.Run("CreateAnalyticsClient", func(t *testing.T) {
		client, err := factory.CreateAnalyticsClient()
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
		HTTPProxy:  "http://http-proxy:8080",
		HTTPSProxy: "https://https-proxy:8080",
		NoProxy:    "localhost,127.0.0.1",
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
