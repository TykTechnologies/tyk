package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/test"
)

// TestUpstreamCertificateExpiryInReverseProxy tests that upstream certificates
// are checked for expiry when loaded in the reverse proxy
func TestUpstreamCertificateExpiryInReverseProxy(t *testing.T) {
	// Configure Tyk to skip upstream SSL verification
	ts := StartTest(func(c *config.Config) {
		c.ProxySSLInsecureSkipVerify = true
		c.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
		c.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 0 // No check cooldown
		c.Security.CertificateExpiryMonitor.EventCooldownSeconds = 1 // 1 second event cooldown
	})
	defer ts.Close()

	// Generate an expiring certificate (expires in 15 days)
	expiringCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.upstream.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(15 * 24 * time.Hour), // Expires in 15 days
	}
	_, _, combinedPEM, tlsCert := certs.GenCertificate(expiringCert, false)
	var err error
	tlsCert.Leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
	assert.NoError(t, err, "Failed to parse certificate")

	// Create upstream server that requires mTLS
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			t.Errorf("Failed to write response in test server: %v", err)
		}
	}))

	pool := x509.NewCertPool()
	pool.AddCert(tlsCert.Leaf)
	upstream.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	// Add certificate to CertificateManager
	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
	require.NoError(t, err, "Failed to add certificate to manager")
	defer ts.Gw.CertificateManager.Delete(certID, "")

	// Track events
	eventTracker := &MockEventTracker{}
	err = eventTracker.Init(nil)
	require.NoError(t, err, "Failed to initialize event tracker")

	// Build API with upstream mTLS
	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.StripListenPath = true
		spec.UpstreamCertificates = map[string]string{
			"*": certID, // Use wildcard to match any upstream
		}
		spec.UpstreamCertificatesDisabled = false
	})[0]

	// Register event handlers AFTER BuildAndLoadAPI
	// (EventPaths is a runtime field not preserved by BuildAndLoadAPI)
	api.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		event.CertificateExpiringSoon: {eventTracker},
		event.CertificateExpired:      {eventTracker},
	}

	// Make first request to trigger lazy initialization of batcher
	ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})

	// Set short flush interval immediately after first request
	require.NotNil(t, api.UpstreamCertExpiryBatcher, "Batcher should be initialized after first request")
	api.UpstreamCertExpiryBatcher.SetFlushInterval(50 * time.Millisecond)

	// Make requests to add cert to batch and wait for flush
	for i := 0; i < 2; i++ {
		ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	// Verify event was fired
	events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
	assert.NotEmpty(t, events, "Expected CertificateExpiringSoon event to be fired")

	if len(events) > 0 {
		meta, ok := events[0].Meta.(certcheck.EventCertificateExpiringSoonMeta)
		assert.True(t, ok, "Event meta should be EventCertificateExpiringSoonMeta")
		assert.Equal(t, "upstream", meta.CertRole, "Certificate role should be 'upstream'")
		assert.Equal(t, api.APIID, meta.APIID, "APIID should match")
		assert.NotEmpty(t, meta.CertName, "Certificate name should be set")
		assert.Greater(t, meta.DaysRemaining, 0, "Days remaining should be positive")
		assert.Less(t, meta.DaysRemaining, 30, "Days remaining should be less than threshold")
	}
}

// TestUpstreamCertificateExpiryEventCooldown tests that event cooldown works for upstream certificates
func TestUpstreamCertificateExpiryEventCooldown(t *testing.T) {
	// Configure Tyk to skip upstream SSL verification
	ts := StartTest(func(c *config.Config) {
		c.ProxySSLInsecureSkipVerify = true
		c.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
		c.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 0    // No check cooldown
		c.Security.CertificateExpiryMonitor.EventCooldownSeconds = 3600 // 1 hour event cooldown
	})
	defer ts.Close()

	// Generate an expiring certificate (expires in 15 days)
	expiringCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test.upstream.com",
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(15 * 24 * time.Hour),
	}
	_, _, combinedPEM, tlsCert := certs.GenCertificate(expiringCert, false)
	var err error
	tlsCert.Leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
	assert.NoError(t, err, "Failed to parse certificate")

	// Create upstream server
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	pool := x509.NewCertPool()
	pool.AddCert(tlsCert.Leaf)
	upstream.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	certID, err := ts.Gw.CertificateManager.Add(combinedPEM, "")
	require.NoError(t, err, "Failed to add certificate to manager")
	defer ts.Gw.CertificateManager.Delete(certID, "")

	eventTracker := &MockEventTracker{}
	err = eventTracker.Init(nil)
	require.NoError(t, err, "Failed to initialize event tracker")

	// Build API with event cooldown enabled
	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.Proxy.TargetURL = upstream.URL
		spec.UpstreamCertificates = map[string]string{
			"*": certID,
		}
	})[0]

	// Register event handlers AFTER BuildAndLoadAPI
	api.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
		event.CertificateExpiringSoon: {eventTracker},
	}

	// Make first request to trigger lazy initialization
	ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})

	// Set short flush interval
	require.NotNil(t, api.UpstreamCertExpiryBatcher, "Batcher should be initialized")
	api.UpstreamCertExpiryBatcher.SetFlushInterval(50 * time.Millisecond)

	// Make requests to add cert to batch and wait for flush
	for i := 0; i < 2; i++ {
		ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	firstEventCount := eventTracker.GetEventCount()
	assert.Greater(t, firstEventCount, 0, "First batch should fire event")

	// Make more requests - should not fire new events due to cooldown
	for i := 0; i < 2; i++ {
		ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	secondEventCount := eventTracker.GetEventCount()
	assert.Equal(t, firstEventCount, secondEventCount, "Additional batches should not fire events due to cooldown")
}
