package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

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
				InsecureSkipVerify: true, // For test server
			},
		},
	}
	ts.Gw.SetConfig(gwConf)

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
	ts := StartTest(nil)
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
				HTTPProxy: "invalid://proxy:8080",
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

	// Perform health check - should work despite invalid proxy (fallback)
	checker.CheckHost(hostData)

	// Give some time for the health check to be processed
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

	// Perform health check - should timeout quickly
	start := time.Now()
	checker.CheckHost(hostData)
	duration := time.Since(start)

	// Should timeout quickly, not wait for the full server delay
	assert.Less(t, duration, 1*time.Second, "Health check should timeout quickly")
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

	// Perform health check
	checker.CheckHost(hostData)

	// Give some time for the health check to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify custom headers were sent
	assert.Equal(t, "test-value", receivedHeaders["X-Custom-Header"])
	assert.Equal(t, "Bearer test-token", receivedHeaders["Authorization"])
	assert.Equal(t, "tyk-gateway", receivedHeaders["X-Health-Source"])
	assert.Equal(t, "close", receivedHeaders["Connection"]) // Should always be set to close
}
