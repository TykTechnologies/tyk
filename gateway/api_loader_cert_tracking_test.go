package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLoadApps_CertificateTracking tests that loadApps correctly updates the certificate usage tracker
func TestLoadApps_CertificateTracking(t *testing.T) {
	t.Run("nil tracker - no panic", func(t *testing.T) {
		// Create a test gateway with StartTest
		ts := StartTest(nil)
		defer ts.Close()

		// Ensure certUsageTracker is nil (default for non-RPC mode)
		assert.Nil(t, ts.Gw.certUsageTracker)

		// Create test specs with certificates
		spec1 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api1"
			spec.Proxy.ListenPath = "/api1/"
			spec.Certificates = []string{"cert1"}
		})[0]

		spec2 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api2"
			spec.Proxy.ListenPath = "/api2/"
			spec.ClientCertificates = []string{"cert2"}
		})[0]

		// loadApps should not panic with nil tracker
		assert.NotPanics(t, func() {
			ts.Gw.loadApps([]*APISpec{spec1, spec2})
		})
	})

	t.Run("with tracker - updates certificate usage map", func(t *testing.T) {
		// Create a test gateway
		ts := StartTest(nil)
		defer ts.Close()

		// Enable RPC mode and create tracker
		cfg := ts.Gw.GetConfig()
		cfg.SlaveOptions.UseRPC = true
		cfg.SlaveOptions.SyncUsedCertsOnly = true
		cfg.HttpServerOptions.SSLCertificates = []string{"server-cert1", "server-cert2"}
		ts.Gw.SetConfig(cfg)

		// Initialize cert usage tracker (normally done in RPC mode setup)
		ts.Gw.certUsageTracker = newUsageTracker()

		// Verify tracker starts empty
		assert.Equal(t, 0, ts.Gw.certUsageTracker.Len())

		// Create test specs with certificates
		spec1 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api1"
			spec.Proxy.ListenPath = "/api1/"
			spec.Certificates = []string{"cert1", "cert2"}
		})[0]

		spec2 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api2"
			spec.Proxy.ListenPath = "/api2/"
			spec.ClientCertificates = []string{"cert3"}
			spec.UpstreamCertificates = map[string]string{"upstream": "cert4"}
		})[0]

		// Load APIs
		ts.Gw.loadApps([]*APISpec{spec1, spec2})

		// Verify tracker was updated with certificates from specs + server certs
		// Expected: cert1, cert2, cert3, cert4 (from APIs) + server-cert1, server-cert2 (from config)
		assert.Equal(t, 6, ts.Gw.certUsageTracker.Len())

		// Verify specific certificates are tracked
		assert.True(t, ts.Gw.certUsageTracker.Required("cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("cert2"))
		assert.True(t, ts.Gw.certUsageTracker.Required("cert3"))
		assert.True(t, ts.Gw.certUsageTracker.Required("cert4"))
		assert.True(t, ts.Gw.certUsageTracker.Required("server-cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("server-cert2"))

		// Verify API associations
		apis := ts.Gw.certUsageTracker.APIs("cert1")
		assert.Contains(t, apis, "api1")

		apis = ts.Gw.certUsageTracker.APIs("cert3")
		assert.Contains(t, apis, "api2")

		apis = ts.Gw.certUsageTracker.APIs("server-cert1")
		assert.Contains(t, apis, "__server__")
	})

	t.Run("replace on reload - old certs removed", func(t *testing.T) {
		// Create a test gateway
		ts := StartTest(nil)
		defer ts.Close()

		// Setup RPC mode with tracker
		cfg := ts.Gw.GetConfig()
		cfg.SlaveOptions.UseRPC = true
		cfg.SlaveOptions.SyncUsedCertsOnly = true
		ts.Gw.SetConfig(cfg)

		ts.Gw.certUsageTracker = newUsageTracker()

		// Load initial set of APIs
		spec1 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api1"
			spec.Proxy.ListenPath = "/api1/"
			spec.Certificates = []string{"old-cert1", "old-cert2"}
		})[0]

		ts.Gw.loadApps([]*APISpec{spec1})

		// Verify initial certs are tracked
		assert.True(t, ts.Gw.certUsageTracker.Required("old-cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("old-cert2"))
		assert.Equal(t, 2, ts.Gw.certUsageTracker.Len())

		// Load new set of APIs (simulating reload)
		spec2 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api2"
			spec.Proxy.ListenPath = "/api2/"
			spec.Certificates = []string{"new-cert1", "new-cert2"}
		})[0]

		ts.Gw.loadApps([]*APISpec{spec2})

		// Verify old certs are gone and new certs are tracked
		assert.False(t, ts.Gw.certUsageTracker.Required("old-cert1"))
		assert.False(t, ts.Gw.certUsageTracker.Required("old-cert2"))
		assert.True(t, ts.Gw.certUsageTracker.Required("new-cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("new-cert2"))
		assert.Equal(t, 2, ts.Gw.certUsageTracker.Len())
	})

	t.Run("empty specs - clears tracker except server certs", func(t *testing.T) {
		// Create a test gateway
		ts := StartTest(nil)
		defer ts.Close()

		// Setup RPC mode with tracker and server certs
		cfg := ts.Gw.GetConfig()
		cfg.SlaveOptions.UseRPC = true
		cfg.SlaveOptions.SyncUsedCertsOnly = true
		cfg.HttpServerOptions.SSLCertificates = []string{"server-cert"}
		ts.Gw.SetConfig(cfg)

		ts.Gw.certUsageTracker = newUsageTracker()

		// Load initial API
		spec1 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api1"
			spec.Proxy.ListenPath = "/api1/"
			spec.Certificates = []string{"cert1"}
		})[0]

		ts.Gw.loadApps([]*APISpec{spec1})

		assert.True(t, ts.Gw.certUsageTracker.Required("cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("server-cert"))
		assert.Equal(t, 2, ts.Gw.certUsageTracker.Len())

		// Load empty specs (simulating all APIs unloaded)
		ts.Gw.loadApps([]*APISpec{})

		// API certs should be gone, but server cert remains
		assert.False(t, ts.Gw.certUsageTracker.Required("cert1"))
		assert.True(t, ts.Gw.certUsageTracker.Required("server-cert"))
		assert.Equal(t, 1, ts.Gw.certUsageTracker.Len())
	})

	t.Run("duplicate certs across APIs - tracked once", func(t *testing.T) {
		// Create a test gateway
		ts := StartTest(nil)
		defer ts.Close()

		// Setup RPC mode with tracker
		cfg := ts.Gw.GetConfig()
		cfg.SlaveOptions.UseRPC = true
		cfg.SlaveOptions.SyncUsedCertsOnly = true
		ts.Gw.SetConfig(cfg)

		ts.Gw.certUsageTracker = newUsageTracker()

		// Multiple APIs using the same certificates
		spec1 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api1"
			spec.Proxy.ListenPath = "/api1/"
			spec.Certificates = []string{"shared-cert"}
		})[0]

		spec2 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api2"
			spec.Proxy.ListenPath = "/api2/"
			spec.Certificates = []string{"shared-cert"}
		})[0]

		spec3 := BuildAPI(func(spec *APISpec) {
			spec.APIID = "api3"
			spec.Proxy.ListenPath = "/api3/"
			spec.ClientCertificates = []string{"shared-cert"}
		})[0]

		ts.Gw.loadApps([]*APISpec{spec1, spec2, spec3})

		// Cert should only be tracked once
		assert.Equal(t, 1, ts.Gw.certUsageTracker.Len())
		assert.True(t, ts.Gw.certUsageTracker.Required("shared-cert"))

		// But should be associated with all three APIs
		apis := ts.Gw.certUsageTracker.APIs("shared-cert")
		assert.Len(t, apis, 3)
		assert.Contains(t, apis, "api1")
		assert.Contains(t, apis, "api2")
		assert.Contains(t, apis, "api3")
	})
}
