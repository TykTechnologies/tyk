package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/test"
)

// TestUpstreamCertificateExpiryInReverseProxy tests that upstream certificates
// are checked for expiry when loaded in the reverse proxy
func TestUpstreamCertificateExpiryInReverseProxy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Generate an expiring certificate (expires in 15 days)
	expiringCert := &x509.Certificate{
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(15 * 24 * time.Hour), // Expires in 15 days
	}
	_, _, combinedPEM, tlsCert := certs.GenCertificate(expiringCert, false)
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])

	// Create upstream server that requires mTLS
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
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
	certID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(certID, "")

	// Track events
	eventTracker := &MockEventTracker{}
	ts.Gw.FireSystemEvent(event.CertificateExpiringSoon, certcheck.EventCertificateExpiringSoonMeta{})
	ts.Gw.FireSystemEvent(event.CertificateExpired, certcheck.EventCertificateExpiredMeta{})

	// Build API with upstream mTLS
	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.Proxy.TargetURL = upstream.URL
		spec.Proxy.StripListenPath = true
		spec.UpstreamCertificates = map[string]string{
			upstream.Listener.Addr().String(): certID,
		}
		spec.UpstreamCertificatesDisabled = false

		// Enable certificate expiry monitoring
		spec.GlobalConfig.Security.CertificateExpiryMonitor.Enabled = true
		spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
		spec.GlobalConfig.Security.CertificateExpiryMonitor.CheckCooldownSeconds = 1
		spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 0 // No cooldown for testing

		// Register event handler
		spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
			event.CertificateExpiringSoon: {eventTracker},
			event.CertificateExpired:      {eventTracker},
		}
	})[0]

	// Make request that triggers upstream connection
	_, err := ts.Run(t, test.TestCase{
		Path: "/test/",
		Code: http.StatusOK,
	})
	assert.NoError(t, err)

	// Wait a bit for event processing
	time.Sleep(100 * time.Millisecond)

	// Verify event was fired
	events := eventTracker.GetEventsByType(event.CertificateExpiringSoon)
	assert.NotEmpty(t, events, "Expected CertificateExpiringSoon event to be fired")

	if len(events) > 0 {
		meta, ok := events[0].Meta.(certcheck.EventCertificateExpiringSoonMeta)
		assert.True(t, ok, "Event meta should be EventCertificateExpiringSoonMeta")
		assert.Equal(t, "upstream", meta.CertRole, "Certificate role should be 'upstream'")
		assert.Equal(t, api.APIID, meta.APIID, "APIID should match")
		assert.Greater(t, meta.DaysRemaining, 0, "Days remaining should be positive")
		assert.Less(t, meta.DaysRemaining, 30, "Days remaining should be less than threshold")
	}
}

// TestUpstreamCertificateExpiryEventCooldown tests that event cooldown works for upstream certificates
func TestUpstreamCertificateExpiryEventCooldown(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Generate an expiring certificate (expires in 15 days)
	expiringCert := &x509.Certificate{
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(15 * 24 * time.Hour),
	}
	_, _, combinedPEM, tlsCert := certs.GenCertificate(expiringCert, false)
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])

	// Create upstream server
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	certID, _ := ts.Gw.CertificateManager.Add(combinedPEM, "")
	defer ts.Gw.CertificateManager.Delete(certID, "")

	eventTracker := &MockEventTracker{}

	// Build API with event cooldown enabled
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.Proxy.TargetURL = upstream.URL
		spec.UpstreamCertificates = map[string]string{
			upstream.Listener.Addr().String(): certID,
		}

		spec.GlobalConfig.Security.CertificateExpiryMonitor.Enabled = true
		spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
		spec.GlobalConfig.Security.CertificateExpiryMonitor.EventCooldownSeconds = 3600 // 1 hour cooldown

		spec.EventPaths = map[apidef.TykEvent][]config.TykEventHandler{
			event.CertificateExpiringSoon: {eventTracker},
		}
	})

	// Make first request
	ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})
	time.Sleep(100 * time.Millisecond)

	firstEventCount := eventTracker.GetEventCount()
	assert.Greater(t, firstEventCount, 0, "First request should fire event")

	// Make second request immediately
	ts.Run(t, test.TestCase{Path: "/test/", Code: http.StatusOK})
	time.Sleep(100 * time.Millisecond)

	secondEventCount := eventTracker.GetEventCount()
	assert.Equal(t, firstEventCount, secondEventCount, "Second request should not fire event due to cooldown")
}
