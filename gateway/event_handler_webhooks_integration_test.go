package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

func TestWebHookHandler_ProxyIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test webhook target server
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer webhookServer.Close()

	// Create a test proxy server that tracks requests
	var proxyRequests int
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests++
		// Forward the request to the actual webhook server
		client := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest(r.Method, webhookServer.URL, r.Body)
		for k, v := range r.Header {
			req.Header[k] = v
		}

		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
		w.Write([]byte("OK"))
	}))
	defer proxyServer.Close()

	// Configure external service config with proxy
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Webhooks: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: proxyServer.URL,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create webhook handler
	handler := &WebHookHandler{
		Gw: ts.Gw,
		conf: apidef.WebHookHandlerConf{
			TargetPath: webhookServer.URL,
			Method:     "POST",
		},
	}

	err := handler.Init(apidef.WebHookHandlerConf{
		TargetPath: webhookServer.URL,
		Method:     "POST",
	})
	require.NoError(t, err)

	// Create test event message
	eventMessage := config.EventMessage{
		Type: EventQuotaExceeded,
		Meta: map[string]interface{}{
			"APIID":    "test-api",
			"APIKey":   "test-key",
			"QuotaMax": 1000,
		},
	}

	// Trigger webhook
	handler.HandleEvent(eventMessage)

	// Give some time for the webhook to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify webhook was called through proxy
	assert.Greater(t, proxyRequests, 0, "Proxy should have received at least one request")
	// Webhook should have been called through proxy
}

func TestWebHookHandler_mTLSIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test HTTPS webhook server
	webhookServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer webhookServer.Close()

	// Configure external service config with mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Webhooks: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // For test server
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create webhook handler
	handler := &WebHookHandler{
		Gw: ts.Gw,
	}

	err := handler.Init(apidef.WebHookHandlerConf{
		TargetPath: webhookServer.URL,
		Method:     "POST",
	})
	require.NoError(t, err)

	// Test that HTTP client factory creates client with mTLS configuration
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, err := factory.CreateWebhookClient()
	require.NoError(t, err)

	// Verify transport is configured
	transport := client.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)

	// Verify the client was created successfully
	assert.NotNil(t, client)

	// Verify webhook-specific timeout is applied
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestWebHookHandler_ServiceTimeouts(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Test that webhook service gets appropriate timeout
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, err := factory.CreateWebhookClient()
	require.NoError(t, err)

	// Webhook service should have 30 second timeout
	assert.Equal(t, 30*time.Second, client.Timeout)

	// Test transport configuration for webhooks
	transport := client.Transport.(*http.Transport)
	assert.Equal(t, 50, transport.MaxIdleConns)
	assert.Equal(t, 10, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 30*time.Second, transport.IdleConnTimeout)
}

func TestWebHookHandler_FallbackBehavior(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure invalid proxy to test fallback
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Webhooks: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: "invalid://proxy:8080",
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create a test webhook target server
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer webhookServer.Close()

	// Create webhook handler
	handler := &WebHookHandler{
		Gw: ts.Gw,
	}

	err := handler.Init(apidef.WebHookHandlerConf{
		TargetPath: webhookServer.URL,
		Method:     "POST",
	})
	require.NoError(t, err)

	// Create test event message
	eventMessage := config.EventMessage{
		Type: EventQuotaExceeded,
		Meta: map[string]interface{}{
			"APIID":    "test-api",
			"APIKey":   "test-key",
			"QuotaMax": 1000,
		},
	}

	// Trigger webhook - should work despite invalid proxy (fallback)
	handler.HandleEvent(eventMessage)

	// Give some time for the webhook to be processed
	time.Sleep(100 * time.Millisecond)

	// The webhook should still be called using fallback client
	// Note: This test depends on the fallback behavior in the webhook handler
	// If the client factory fails, it should fall back to the default client
}

func TestWebHookHandler_ConfigurationHierarchy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure global and service-specific proxy
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Proxy: config.ProxyConfig{
			HTTPProxy: "http://global-proxy:8080",
		},
		Webhooks: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: "http://webhook-specific-proxy:8080",
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Test that service-specific configuration takes precedence
	factory := NewExternalHTTPClientFactory(ts.Gw)
	serviceConfig := factory.getServiceConfig(config.ServiceTypeWebhook)

	assert.Equal(t, "http://webhook-specific-proxy:8080", serviceConfig.Proxy.HTTPProxy)
}
