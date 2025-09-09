package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
)

// Mock certificate manager for testing
type mockWebhookCertificateManager struct {
	certificates   map[string]*tls.Certificate
	caCertificates []string
}

func (m *mockWebhookCertificateManager) List(certIDs []string, _ certs.CertificateType) (out []*tls.Certificate) {
	for _, id := range certIDs {
		if cert, exists := m.certificates[id]; exists {
			out = append(out, cert)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (m *mockWebhookCertificateManager) ListPublicKeys(_ []string) (out []string) {
	return []string{}
}

func (m *mockWebhookCertificateManager) ListRawPublicKey(_ string) interface{} {
	return nil
}

func (m *mockWebhookCertificateManager) ListAllIds(_ string) []string {
	var ids []string
	for id := range m.certificates {
		ids = append(ids, id)
	}
	return ids
}

func (m *mockWebhookCertificateManager) GetRaw(_ string) (string, error) {
	return "", nil
}

func (m *mockWebhookCertificateManager) Add(_ []byte, _ string) (string, error) {
	return "", nil
}

func (m *mockWebhookCertificateManager) Delete(_ string, _ string) {}

func (m *mockWebhookCertificateManager) CertPool(certIDs []string) *x509.CertPool {
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

func (m *mockWebhookCertificateManager) FlushCache() {}

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
				CACertIDs:          []string{"test-ca-cert"}, // Dummy CA cert for validation
				InsecureSkipVerify: true,                     // For test server
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Add mock certificate manager for CA certificate
	mockCertManager := &mockWebhookCertificateManager{
		certificates:   map[string]*tls.Certificate{},
		caCertificates: []string{"test-ca-cert"},
	}
	ts.Gw.CertificateManager = mockCertManager

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
		Global: config.GlobalProxyConfig{
			Enabled:   true,
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
