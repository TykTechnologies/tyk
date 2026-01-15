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

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
)

// Mock certificate manager for host checker integration testing
type mockHostCheckerCertificateManager struct {
	certificates   map[string]*tls.Certificate
	caCertificates []string
}

func (m *mockHostCheckerCertificateManager) List(certIDs []string, _ certs.CertificateType) (out []*tls.Certificate) {
	for _, id := range certIDs {
		if cert, exists := m.certificates[id]; exists {
			out = append(out, cert)
		} else {
			out = append(out, nil)
		}
	}
	return out
}

func (m *mockHostCheckerCertificateManager) ListPublicKeys(_ []string) (out []string) {
	return []string{}
}

func (m *mockHostCheckerCertificateManager) ListRawPublicKey(_ string) interface{} {
	return nil
}

func (m *mockHostCheckerCertificateManager) ListAllIds(_ string) []string {
	var ids []string
	for id := range m.certificates {
		ids = append(ids, id)
	}
	return ids
}

func (m *mockHostCheckerCertificateManager) GetRaw(_ string) (string, error) {
	return "", nil
}

func (m *mockHostCheckerCertificateManager) Add(_ []byte, _ string) (string, error) {
	return "", nil
}

func (m *mockHostCheckerCertificateManager) Delete(_ string, _ string) {}

func (m *mockHostCheckerCertificateManager) CertPool(certIDs []string) *x509.CertPool {
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

func (m *mockHostCheckerCertificateManager) FlushCache() {}

func (m *mockHostCheckerCertificateManager) SetRegistry(_ certs.CertRegistry) {}

func TestHostChecker_ProxyIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test health endpoint server
	var healthCheckCalled bool
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		healthCheckCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer healthServer.Close()

	// Create a test proxy server that tracks requests
	var proxyRequests int
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests++
		// Forward the request to the actual health server
		client := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest(r.Method, healthServer.URL, r.Body)
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
		Health: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: proxyServer.URL,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create host checker and initialize it with buffered channels
	checker := &HostUptimeChecker{
		Gw: ts.Gw,
	}
	checker.Init(1, 3, 5, make(map[string]HostData), HostCheckCallBacks{})

	// Create test host data
	hostData := HostData{
		CheckURL: healthServer.URL,
		Method:   "GET",
		Timeout:  5 * time.Second,
	}

	// Create a channel to signal completion
	done := make(chan bool, 1)

	// Consume from the channels to prevent blocking
	go func() {
		select {
		case <-checker.okChan:
			done <- true
		case <-checker.errorChan:
			done <- false
		case <-time.After(10 * time.Second):
			done <- false // timeout
		}
	}()

	// Perform health check in a goroutine to avoid blocking
	go checker.CheckHost(hostData)

	// Wait for completion or timeout
	success := <-done
	assert.True(t, success, "Health check should succeed")

	// Give some time for any remaining processing
	time.Sleep(100 * time.Millisecond)

	// Verify health check was performed through proxy
	assert.Greater(t, proxyRequests, 0, "Proxy should have received at least one request")
	assert.True(t, healthCheckCalled, "Health endpoint should have been called")
}

func TestHostChecker_mTLSIntegration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test HTTPS health endpoint server
	healthServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer healthServer.Close()

	// Configure external service config with mTLS
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Health: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				CACertIDs:          []string{"test-ca-cert"},
				InsecureSkipVerify: true,
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Add mock certificate manager for CA certificate
	mockCertManager := &mockHostCheckerCertificateManager{
		certificates:   map[string]*tls.Certificate{},
		caCertificates: []string{"test-ca-cert"},
	}
	ts.Gw.CertificateManager = mockCertManager

	// Test that HTTP client factory creates client with mTLS configuration
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)

	// Verify transport is configured
	transport := client.Transport.(*http.Transport)
	assert.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)

	// Verify the client was created successfully
	assert.NotNil(t, client)

	// Verify health check-specific timeout is applied
	assert.Equal(t, 10*time.Second, client.Timeout)
}

func TestHostChecker_ServiceTimeouts(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		// Enable external services for health check testing
		globalConf.ExternalServices.Global.Enabled = true
	})
	defer ts.Close()

	// Test that health check service gets appropriate timeout
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, err := factory.CreateHealthCheckClient()
	require.NoError(t, err)

	// Health check service should have 10 second timeout (quick responses needed)
	assert.Equal(t, 10*time.Second, client.Timeout)

	// Test transport configuration for health checks
	transport := client.Transport.(*http.Transport)
	assert.Equal(t, 20, transport.MaxIdleConns)
	assert.Equal(t, 5, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 15*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 5*time.Second, transport.TLSHandshakeTimeout)
}

func TestHostChecker_FallbackBehavior(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Configure invalid proxy to test fallback
	gwConf := ts.Gw.GetConfig()
	gwConf.ExternalServices = config.ExternalServiceConfig{
		Health: config.ServiceConfig{
			Proxy: config.ProxyConfig{
				HTTPProxy: "://invalid-proxy", // Malformed URL that will cause url.Parse to fail
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

	// Create a test health endpoint server
	var healthCheckCalled bool
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		healthCheckCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer healthServer.Close()

	// Create host checker and initialize it with buffered channels
	checker := &HostUptimeChecker{
		Gw: ts.Gw,
	}
	checker.Init(1, 3, 5, make(map[string]HostData), HostCheckCallBacks{})

	// Create test host data
	hostData := HostData{
		CheckURL: healthServer.URL,
		Method:   "GET",
		Timeout:  5 * time.Second,
	}

	// Create a channel to signal completion
	done := make(chan bool, 1)

	// Consume from the channels to prevent blocking
	go func() {
		select {
		case report := <-checker.okChan:
			t.Logf("Received OK report: %+v", report)
			done <- true
		case report := <-checker.errorChan:
			t.Logf("Received ERROR report: %+v", report)
			done <- false
		case <-time.After(10 * time.Second):
			t.Logf("Timed out waiting for health check result")
			done <- false // timeout
		}
	}()

	// Add debugging for the client creation
	factory := NewExternalHTTPClientFactory(ts.Gw)
	client, clientErr := factory.CreateHealthCheckClient()
	t.Logf("Client creation error: %v", clientErr)
	if clientErr == nil {
		t.Logf("Client created successfully, timeout: %v", client.Timeout)
	}

	// Perform health check in a goroutine to avoid blocking
	go checker.CheckHost(hostData)

	// Wait for completion or timeout
	success := <-done
	assert.True(t, success, "Health check should succeed")

	// Give some time for any remaining processing
	time.Sleep(100 * time.Millisecond)

	// The health check should still be performed using fallback client
	assert.True(t, healthCheckCalled, "Health endpoint should have been called despite proxy failure")
}

func TestHostChecker_TimeoutOverride(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create host checker and initialize it with buffered channels
	checker := &HostUptimeChecker{
		Gw: ts.Gw,
	}
	checker.Init(1, 3, 5, make(map[string]HostData), HostCheckCallBacks{})

	// Create a slow server to test timeout behavior
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second) // Longer than our test timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	// Create test host data with short timeout
	hostData := HostData{
		CheckURL: slowServer.URL,
		Method:   "GET",
		Timeout:  100 * time.Millisecond, // Very short timeout
	}

	// Create a channel to signal completion
	done := make(chan bool, 1)

	// Consume from the channels to prevent blocking
	go func() {
		select {
		case <-checker.okChan:
			done <- false // Should not succeed due to timeout
		case <-checker.errorChan:
			done <- true // Expected timeout error
		case <-time.After(5 * time.Second):
			done <- false // Test timeout
		}
	}()

	// Perform health check - should timeout quickly
	start := time.Now()
	go checker.CheckHost(hostData)

	// Wait for completion or timeout
	timeoutOccurred := <-done
	duration := time.Since(start)

	// Should timeout quickly, not wait for the full server delay
	assert.Less(t, duration, 1*time.Second, "Health check should timeout quickly")
	assert.True(t, timeoutOccurred, "Health check should timeout and report error")
}

func TestHostChecker_CustomHeaders(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a test health endpoint server that checks headers
	var receivedHeaders map[string]string
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				receivedHeaders[k] = v[0]
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer healthServer.Close()

	// Create host checker and initialize it with buffered channels
	checker := &HostUptimeChecker{
		Gw: ts.Gw,
	}
	checker.Init(1, 3, 5, make(map[string]HostData), HostCheckCallBacks{})

	// Create test host data with custom headers
	hostData := HostData{
		CheckURL: healthServer.URL,
		Method:   "GET",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
			"Authorization":   "Bearer test-token",
			"X-Health-Source": "tyk-gateway",
		},
		Timeout: 5 * time.Second,
	}

	// Create a channel to signal completion
	done := make(chan bool, 1)

	// Consume from the channels to prevent blocking
	go func() {
		select {
		case <-checker.okChan:
			done <- true
		case <-checker.errorChan:
			done <- false
		case <-time.After(10 * time.Second):
			done <- false // timeout
		}
	}()

	// Perform health check in a goroutine to avoid blocking
	go checker.CheckHost(hostData)

	// Wait for completion or timeout
	success := <-done
	assert.True(t, success, "Health check should succeed")

	// Give some time for any remaining processing
	time.Sleep(100 * time.Millisecond)

	// Verify custom headers were sent
	assert.Equal(t, "test-value", receivedHeaders["X-Custom-Header"])
	assert.Equal(t, "Bearer test-token", receivedHeaders["Authorization"])
	assert.Equal(t, "tyk-gateway", receivedHeaders["X-Health-Source"])
	assert.Equal(t, "close", receivedHeaders["Connection"]) // Should always be set to close
}
