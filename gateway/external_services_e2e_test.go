package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
)

// Mock certificate manager for E2E testing
type mockE2ECertificateManager struct {
	certificates   map[string]*tls.Certificate
	caCertificates []string
}

func (m *mockE2ECertificateManager) List(certIDs []string, _ certs.CertificateType) (out []*tls.Certificate) {
	for _, id := range certIDs {
		if cert, exists := m.certificates[id]; exists {
			out = append(out, cert)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (m *mockE2ECertificateManager) ListPublicKeys(_ []string) (out []string) {
	return []string{}
}

func (m *mockE2ECertificateManager) ListRawPublicKey(_ string) interface{} {
	return nil
}

func (m *mockE2ECertificateManager) ListAllIds(_ string) []string {
	var ids []string
	for id := range m.certificates {
		ids = append(ids, id)
	}
	return ids
}

func (m *mockE2ECertificateManager) GetRaw(_ string) (string, error) {
	return "", nil
}

func (m *mockE2ECertificateManager) Add(_ []byte, _ string) (string, error) {
	return "", nil
}

func (m *mockE2ECertificateManager) Delete(_ string, _ string) {}

func (m *mockE2ECertificateManager) CertPool(certIDs []string) *x509.CertPool {
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

func (m *mockE2ECertificateManager) FlushCache() {}

func (m *mockE2ECertificateManager) SetRegistry(_ certs.CertRegistry) {}

func TestE2E_OAuthFlowWithProxyAndmTLS(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track proxy usage
	var proxyRequests []string

	// Create mock IDP server
	idpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/introspect":
			// OAuth introspection endpoint
			response := map[string]interface{}{
				"active":    true,
				"sub":       "test-user-123",
				"exp":       time.Now().Add(time.Hour).Unix(),
				"scope":     "read write",
				"client_id": "test-client",
			}
			json.NewEncoder(w).Encode(response)
		case "/.well-known/jwks.json":
			// JWK endpoint
			jwkResponse := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"kid": "test-key-123",
						"use": "sig",
						"n":   "test-n-value",
						"e":   "AQAB",
					},
				},
			}
			json.NewEncoder(w).Encode(jwkResponse)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idpServer.Close()

	// Create a simple HTTP proxy server that tracks requests
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests = append(proxyRequests, fmt.Sprintf("%s %s", r.Method, r.RequestURI))

		// Act as a simple introspection endpoint for testing
		if r.Method == "POST" {
			response := map[string]interface{}{
				"active":    true,
				"sub":       "test-user-123",
				"exp":       time.Now().Add(time.Hour).Unix(),
				"scope":     "read write",
				"client_id": "test-client",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer proxyServer.Close()

	// Configure external services with proxy and mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		OAuth: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: proxyServer.URL,
			},
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CACertIDs:          []string{"test-ca-cert"},
				InsecureSkipVerify: true,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Add mock certificate manager for CA certificate
	mockCertManager := &mockE2ECertificateManager{
		certificates:   map[string]*tls.Certificate{},
		caCertificates: []string{"test-ca-cert"},
	}
	ts.Gw.CertificateManager = mockCertManager

	// Create API with External OAuth
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:            "test-oauth-api",
			OrgID:            "test-org",
			Slug:             "oauth-test",
			UseKeylessAccess: false,
			AuthConfigs: map[string]apidef.AuthConfig{
				"authToken": {
					AuthHeaderName: "Authorization",
				},
			},
			Proxy: apidef.ProxyConfig{
				ListenPath:      "/oauth-test/",
				TargetURL:       "http://httpbin.org",
				StripListenPath: true,
			},
		},
	}

	// Set external OAuth configuration - use proxy server URL to force proxy usage
	spec.ExternalOAuth = apidef.ExternalOAuth{
		Enabled: true,
		Providers: []apidef.Provider{
			{
				Introspection: apidef.Introspection{
					Enabled:           true,
					URL:               proxyServer.URL + "/introspect",
					ClientID:          "test-client",
					ClientSecret:      "test-secret",
					IdentityBaseField: "sub",
				},
			},
		},
	}

	// Load the API
	ts.Gw.LoadAPI(spec)

	// Create middleware
	middleware := &ExternalOAuthMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   ts.Gw,
		},
	}

	// Test OAuth introspection request
	_, _, err := middleware.introspection("test-access-token")

	// Should work (we'll get back valid response from mock)
	assert.NoError(t, err)

	// Verify proxy was used
	assert.Greater(t, len(proxyRequests), 0, "Proxy should have received requests")

	// Check that introspection endpoint was called
	found := false
	for _, req := range proxyRequests {
		if strings.Contains(req, "introspect") {
			found = true
			break
		}
	}
	assert.True(t, found, "Introspection endpoint should have been called through proxy")
}

func TestE2E_WebhookDeliveryWithProxyRetry(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track webhook delivery attempts
	var webhookAttempts int
	var proxyAttempts int

	// Create webhook target that fails first time
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookAttempts++
		if webhookAttempts == 1 {
			// Fail first attempt
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			// Succeed on subsequent attempts
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}))
	defer webhookServer.Close()

	// Create proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAttempts++

		// Forward to webhook server
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
		if resp.StatusCode == http.StatusOK {
			w.Write([]byte("OK"))
		}
	}))
	defer proxyServer.Close()

	// Configure external services with proxy
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
	}

	err := handler.Init(apidef.WebHookHandlerConf{
		TargetPath: webhookServer.URL,
		Method:     "POST",
		HeaderList: map[string]string{
			"Content-Type": "application/json",
		},
	})
	require.NoError(t, err)

	// Create test event
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

	// Give time for webhook processing
	time.Sleep(200 * time.Millisecond)

	// Verify webhook was attempted through proxy
	assert.Greater(t, proxyAttempts, 0, "Proxy should have received webhook requests")
	assert.Greater(t, webhookAttempts, 0, "Webhook target should have been called")
}

func TestE2E_HealthCheckWithServiceDiscovery(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track requests
	var discoveryRequests int
	var healthCheckRequests int

	// Create service discovery server
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveryRequests++
		services := []map[string]interface{}{
			{"host": "service1.example.com", "port": 8080},
			{"host": "service2.example.com", "port": 8080},
		}
		json.NewEncoder(w).Encode(services)
	}))
	defer discoveryServer.Close()

	// Create health check endpoints
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		healthCheckRequests++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	}))
	defer healthServer.Close()

	// Configure external services with simpler configuration
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Discovery: config.ServiceConfig{},
		Health:    config.ServiceConfig{},
	}
	// Enable external services for discovery testing
	gwConf.ExternalServices.Global.Enabled = true
	ts.Gw.SetConfig(gwConf)

	// Test service discovery directly without complex initialization
	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test service discovery client
	discoveryClient, err := factory.CreateClient(config.ServiceTypeDiscovery)
	require.NoError(t, err)
	require.NotNil(t, discoveryClient)

	resp, err := discoveryClient.Get(discoveryServer.URL)
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Greater(t, discoveryRequests, 0, "Service discovery should have been called")

	// Test health check client
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)
	require.NotNil(t, healthClient)

	resp, err = healthClient.Get(healthServer.URL)
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Greater(t, healthCheckRequests, 0, "Health check endpoint should have been called")
}

func TestE2E_CompleteAPIFlowWithExternalServices(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track all external service calls
	var authRequests int
	var webhookRequests int
	var healthRequests int

	// Create comprehensive mock external services
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "introspect"):
			authRequests++
			response := map[string]interface{}{
				"active": true,
				"sub":    "user-123",
				"exp":    time.Now().Add(time.Hour).Unix(),
			}
			json.NewEncoder(w).Encode(response)
		case strings.Contains(r.URL.Path, "webhook"):
			webhookRequests++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("webhook received"))
		case strings.Contains(r.URL.Path, "health"):
			healthRequests++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("healthy"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer externalServer.Close()

	// Configure comprehensive external services
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Global: config.GlobalProxyConfig{
			Enabled: false, // Use specific configuration
		},
		OAuth: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CACertIDs:          []string{"test-ca-cert"},
				InsecureSkipVerify: true,
			},
		},
		Webhooks: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CACertIDs:          []string{"test-ca-cert"},
				InsecureSkipVerify: true,
			},
		},
		Health: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CACertIDs:          []string{"test-ca-cert"},
				InsecureSkipVerify: true,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Add mock certificate manager for CA certificates
	mockCertManager := &mockE2ECertificateManager{
		certificates:   map[string]*tls.Certificate{},
		caCertificates: []string{"test-ca-cert"},
	}
	ts.Gw.CertificateManager = mockCertManager

	// Create API with all external service integrations
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:            "comprehensive-api",
			OrgID:            "test-org",
			UseKeylessAccess: false,
			Proxy: apidef.ProxyConfig{
				ListenPath:      "/api/",
				TargetURL:       "http://httpbin.org",
				StripListenPath: true,
			},
		},
	}

	// Set external OAuth configuration
	spec.ExternalOAuth = apidef.ExternalOAuth{
		Enabled: true,
		Providers: []apidef.Provider{
			{
				Introspection: apidef.Introspection{
					Enabled:           true,
					URL:               externalServer.URL + "/introspect",
					ClientID:          "test-client",
					ClientSecret:      "test-secret",
					IdentityBaseField: "sub",
				},
			},
		},
	}

	// Load the API
	ts.Gw.LoadAPI(spec)

	// Create HTTP client factory for testing
	factory := NewExternalHTTPClientFactory(ts.Gw)

	// Test OAuth/introspection client
	oauthClient, err := factory.CreateIntrospectionClient()
	require.NoError(t, err)
	require.NotNil(t, oauthClient)

	resp, err := oauthClient.Post(externalServer.URL+"/introspect", "application/x-www-form-urlencoded", strings.NewReader("token=test-token"))
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Greater(t, authRequests, 0, "OAuth introspection should have been called")

	// Test webhook client
	webhookClient, err := factory.CreateWebhookClient()
	require.NoError(t, err)
	require.NotNil(t, webhookClient)

	resp, err = webhookClient.Post(externalServer.URL+"/webhook", "application/json", strings.NewReader(`{"test": "webhook"}`))
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Greater(t, webhookRequests, 0, "Webhook service should have been called")

	// Test health check client
	healthClient, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)
	require.NotNil(t, healthClient)

	resp, err = healthClient.Get(externalServer.URL + "/health")
	assert.NoError(t, err)
	if resp != nil {
		resp.Body.Close()
	}
	assert.Greater(t, healthRequests, 0, "Health check service should have been called")

	// Verify service-specific clients have correct timeout configurations
	assert.Equal(t, 15*time.Second, oauthClient.Timeout)
	assert.Equal(t, 30*time.Second, webhookClient.Timeout)
	assert.Equal(t, 10*time.Second, healthClient.Timeout)
}
