package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestExternalServices_ProxyIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track proxy requests for different services
	var oauthProxyRequests int
	var webhookProxyRequests int
	var healthProxyRequests int
	var discoveryProxyRequests int

	// Create different target servers
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]interface{}{
			"active": true,
			"sub":    "test-user",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer oauthServer.Close()

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("webhook ok"))
	}))
	defer webhookServer.Close()

	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	}))
	defer healthServer.Close()

	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := []map[string]interface{}{
			{"host": "service1.example.com", "port": 8080},
			{"host": "service2.example.com", "port": 8080},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer discoveryServer.Close()

	// Create service-specific proxy servers
	oauthProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oauthProxyRequests++
		// Forward to OAuth server
		resp, err := http.Get(oauthServer.URL)
		assert.Nil(t, err)
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"active": true,
			"sub":    "test-user",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer oauthProxyServer.Close()

	webhookProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookProxyRequests++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("webhook ok"))
	}))
	defer webhookProxyServer.Close()

	healthProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		healthProxyRequests++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	}))
	defer healthProxyServer.Close()

	discoveryProxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveryProxyRequests++
		response := []map[string]interface{}{
			{"host": "service1.example.com", "port": 8080},
			{"host": "service2.example.com", "port": 8080},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer discoveryProxyServer.Close()

	// Configure service-specific proxies
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: oauthProxyServer.URL,
			},
		},
		Webhooks: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: webhookProxyServer.URL,
			},
		},
		Health: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: healthProxyServer.URL,
			},
		},
		Discovery: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: discoveryProxyServer.URL,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Test OAuth client
	factory := NewExternalHTTPClientFactory(ts.Gw)
	oauthClient, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)
	_, err = oauthClient.Get(oauthServer.URL)
	require.NoError(t, err)
	assert.Greater(t, oauthProxyRequests, 0, "OAuth proxy should have been called")

	// Test Webhook client
	webhookClient, err := factory.CreateWebhookClient()
	require.NoError(t, err)
	_, err = webhookClient.Get(webhookServer.URL)
	require.NoError(t, err)
	assert.Greater(t, webhookProxyRequests, 0, "Webhook proxy should have been called")

	// Test Health check client
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)
	_, err = healthClient.Get(healthServer.URL)
	require.NoError(t, err)
	assert.Greater(t, healthProxyRequests, 0, "Health proxy should have been called")

	// Test Discovery client
	discoveryClient, err := factory.CreateClient(config.ServiceTypeDiscovery)
	require.NoError(t, err)
	_, err = discoveryClient.Get(discoveryServer.URL)
	require.NoError(t, err)
	assert.Greater(t, discoveryProxyRequests, 0, "Discovery proxy should have been called")

	// Verify each service uses its specific proxy
	assert.Equal(t, 1, oauthProxyRequests)
	assert.Equal(t, 1, webhookProxyRequests)
	assert.Equal(t, 1, healthProxyRequests)
	assert.Equal(t, 1, discoveryProxyRequests)
}

func TestExternalServices_mTLSIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create HTTPS servers for different services
	oauthServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := map[string]interface{}{
			"active": true,
			"sub":    "test-user",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer oauthServer.Close()

	webhookServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("webhook ok"))
	}))
	defer webhookServer.Close()

	// Configure service-specific mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // For test servers
			},
		},
		Webhooks: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // For test servers
			},
		},
		Health: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // For test servers
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Test OAuth client with mTLS
	factory := NewExternalHTTPClientFactory(ts.Gw)
	oauthClient, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)

	transport := oauthClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)

	// Test Webhook client with mTLS
	webhookClient, err := factory.CreateWebhookClient()
	require.NoError(t, err)

	transport = webhookClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)

	// Test Health check client with mTLS
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)

	transport = healthClient.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestExternalServices_ServiceSpecificTimeouts(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test OAuth timeout (15 seconds)
	oauthClient, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, oauthClient.Timeout)

	// Test Webhook timeout (30 seconds)
	webhookClient, err := factory.CreateWebhookClient()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, webhookClient.Timeout)

	// Test Health check timeout (10 seconds)
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, healthClient.Timeout)

	// Test Discovery timeout (10 seconds)
	discoveryClient, err := factory.CreateClient(config.ServiceTypeDiscovery)
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, discoveryClient.Timeout)

	// Test Analytics timeout (30 seconds)
	analyticsClient, err := factory.CreateAnalyticsClient()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, analyticsClient.Timeout)
}

func TestExternalServices_TransportConfiguration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test OAuth transport configuration
	oauthClient, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)
	transport := oauthClient.Transport.(*http.Transport)
	assert.Equal(t, 50, transport.MaxIdleConns)
	assert.Equal(t, 10, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 30*time.Second, transport.IdleConnTimeout)

	// Test Health check transport configuration (optimized for quick, frequent calls)
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)
	transport = healthClient.Transport.(*http.Transport)
	assert.Equal(t, 20, transport.MaxIdleConns)
	assert.Equal(t, 5, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 15*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 5*time.Second, transport.TLSHandshakeTimeout)

	// Test Analytics transport configuration (higher throughput)
	analyticsClient, err := factory.CreateAnalyticsClient()
	require.NoError(t, err)
	transport = analyticsClient.Transport.(*http.Transport)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 20, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 60*time.Second, transport.IdleConnTimeout)
}

func TestExternalServices_ConfigurationHierarchy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure global proxy and service-specific overrides
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Proxy: config.ProxyConfig{
			HTTPProxy: "http://global-proxy:8080",
			NoProxy:   "localhost,127.0.0.1",
		},
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: "http://oauth-specific-proxy:8080",
			},
		},
		Webhooks: config.ServiceConfig{
			// No specific proxy - should inherit global
		},
	}
	ts.Gw.SetConfig(gwConf)

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test OAuth service-specific configuration takes precedence
	oauthConfig := factory.getServiceConfig(config.ServiceTypeOAuth)
	assert.Equal(t, "http://oauth-specific-proxy:8080", oauthConfig.Proxy.HTTPProxy)

	// Test Webhook inherits global configuration
	webhookConfig := factory.getServiceConfig(config.ServiceTypeWebhook)
	assert.Equal(t, "http://global-proxy:8080", webhookConfig.Proxy.HTTPProxy)
	assert.Equal(t, "localhost,127.0.0.1", webhookConfig.Proxy.NoProxy)
}

func TestExternalServices_NoProxyConfiguration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure proxy with NO_PROXY list
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Proxy: config.ProxyConfig{
			HTTPProxy: "http://proxy:8080",
			NoProxy:   "localhost,127.0.0.1,*.internal",
		},
	}
	ts.Gw.SetConfig(gwConf)

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test NO_PROXY functionality
	serviceConfig := factory.getServiceConfig(config.ServiceTypeOAuth)

	// Test shouldBypassProxy method
	assert.True(t, factory.shouldBypassProxy("localhost", serviceConfig.Proxy.NoProxy))
	assert.True(t, factory.shouldBypassProxy("127.0.0.1", serviceConfig.Proxy.NoProxy))
	assert.False(t, factory.shouldBypassProxy("example.com", serviceConfig.Proxy.NoProxy))
}

func TestExternalServices_EnvironmentProxyConfiguration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure to use environment variables
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				UseEnvironment: true,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test that environment proxy configuration is used
	serviceConfig := factory.getServiceConfig(config.ServiceTypeOAuth)
	proxyFunc, err := factory.getProxyFunction(serviceConfig)
	require.NoError(t, err)

	// The proxy function should be the standard http.ProxyFromEnvironment
	assert.NotNil(t, proxyFunc)
}
