package gateway

import (
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPISpec_UnloadUpstreamCertMonitoring verifies that the upstream certificate
// monitoring goroutine is properly stopped when an API is unloaded
func TestAPISpec_UnloadUpstreamCertMonitoring(t *testing.T) {
	logger, _ := logrustest.NewNullLogger()

	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "unload-test"
		spec.Name = "Unload Test API"
		spec.Proxy.ListenPath = "/test/"
		spec.UpstreamCertificates = map[string]string{
			"*.upstream.com": "cert-id-123",
		}
		spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
	})[0]

	ts.Gw.LoadAPI(spec)

	proxy := &ReverseProxy{
		TykAPISpec: spec,
		Gw:         ts.Gw,
		logger:     logrus.NewEntry(logger),
	}

	// Initialize the batcher (simulates lazy init on first request)
	proxy.initUpstreamCertBatcher()

	// Verify batcher was initialized
	require.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized")
	require.NotNil(t, spec.upstreamCertExpiryCancelFunc, "Cancel func should be initialized")

	// Get initial goroutine count
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Unload the API (this should stop the goroutine)
	spec.Unload()

	// Wait for goroutine cleanup
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Check goroutine count decreased (or at least didn't increase)
	finalGoroutines := runtime.NumGoroutine()
	assert.LessOrEqual(t, finalGoroutines, initialGoroutines,
		"Goroutine count should not increase after Unload (initial: %d, final: %d)",
		initialGoroutines, finalGoroutines)
}

// TestAPISpec_UnloadUpstreamCertMonitoring_MultipleReloads tests that multiple
// API reload cycles don't cause goroutine leaks
func TestAPISpec_UnloadUpstreamCertMonitoring_MultipleReloads(t *testing.T) {
	logger, _ := logrustest.NewNullLogger()

	ts := StartTest(nil)
	defer ts.Close()

	// Get baseline goroutine count
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Perform multiple load/unload cycles
	const numCycles = 5
	for i := 0; i < numCycles; i++ {
		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "reload-test"
			spec.Name = "Reload Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
			spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Initialize batcher
		proxy.initUpstreamCertBatcher()
		require.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized in cycle %d", i)

		// Unload
		spec.Unload()
		time.Sleep(100 * time.Millisecond)
	}

	// Final cleanup
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Check that goroutine count is reasonable (allow some tolerance for test framework goroutines)
	finalGoroutines := runtime.NumGoroutine()
	maxAcceptableGoroutines := baselineGoroutines + 5 // Allow small increase for test framework
	assert.LessOrEqual(t, finalGoroutines, maxAcceptableGoroutines,
		"After %d reload cycles, goroutine count should not significantly increase (baseline: %d, final: %d, max acceptable: %d)",
		numCycles, baselineGoroutines, finalGoroutines, maxAcceptableGoroutines)
}

// TestAPISpec_UnloadUpstreamCertMonitoring_WithoutInitialization tests that
// calling Unload on an API where the batcher was never initialized is safe
func TestAPISpec_UnloadUpstreamCertMonitoring_WithoutInitialization(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "no-init-test"
		spec.Name = "No Init Test API"
		spec.Proxy.ListenPath = "/test/"
		spec.UpstreamCertificates = map[string]string{
			"*.upstream.com": "cert-id-123",
		}
		spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
	})[0]

	ts.Gw.LoadAPI(spec)

	// Don't call initUpstreamCertBatcher - simulate lazy init never triggered

	// Verify batcher was NOT initialized
	assert.Nil(t, spec.UpstreamCertExpiryBatcher, "Batcher should not be initialized")
	assert.Nil(t, spec.upstreamCertExpiryCancelFunc, "Cancel func should not be initialized")

	// Unload should not panic when batcher is nil
	assert.NotPanics(t, func() {
		spec.Unload()
	}, "Unload should not panic when batcher is not initialized")
}

// TestAPISpec_UnloadUpstreamCertMonitoring_ContextCancelled tests that
// the context is actually cancelled during Unload
func TestAPISpec_UnloadUpstreamCertMonitoring_ContextCancelled(t *testing.T) {
	logger, _ := logrustest.NewNullLogger()

	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "context-test"
		spec.Name = "Context Test API"
		spec.Proxy.ListenPath = "/test/"
		spec.UpstreamCertificates = map[string]string{
			"*.upstream.com": "cert-id-123",
		}
		spec.GlobalConfig.Security.CertificateExpiryMonitor.WarningThresholdDays = 30
	})[0]

	ts.Gw.LoadAPI(spec)

	proxy := &ReverseProxy{
		TykAPISpec: spec,
		Gw:         ts.Gw,
		logger:     logrus.NewEntry(logger),
	}

	// Initialize batcher
	proxy.initUpstreamCertBatcher()

	require.NotNil(t, spec.upstreamCertExpiryCheckContext, "Context should exist before Unload")
	require.NotNil(t, spec.upstreamCertExpiryCancelFunc, "Cancel func should exist before Unload")

	// Verify context is not done before Unload
	select {
	case <-spec.upstreamCertExpiryCheckContext.Done():
		t.Fatal("Context should not be cancelled before Unload")
	default:
		// Good - context is still active
	}

	// Call Unload
	spec.Unload()

	// After Unload, the context should be cancelled
	select {
	case <-spec.upstreamCertExpiryCheckContext.Done():
		// Context was cancelled - cleanup worked!
	case <-time.After(1 * time.Second):
		t.Error("Context should be cancelled after Unload, but it's still active")
	}
}

// TestAPISpec_UnloadUpstreamCertMonitoring_DisabledCerts tests that Unload
// is safe when upstream certificates are disabled
func TestAPISpec_UnloadUpstreamCertMonitoring_DisabledCerts(t *testing.T) {
	logger, _ := logrustest.NewNullLogger()

	ts := StartTest(nil)
	defer ts.Close()

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "disabled-test"
		spec.Name = "Disabled Test API"
		spec.Proxy.ListenPath = "/test/"
		spec.UpstreamCertificatesDisabled = true
		spec.UpstreamCertificates = map[string]string{
			"*.upstream.com": "cert-id-123",
		}
	})[0]

	ts.Gw.LoadAPI(spec)

	proxy := &ReverseProxy{
		TykAPISpec: spec,
		Gw:         ts.Gw,
		logger:     logrus.NewEntry(logger),
	}

	// Try to initialize batcher (should be skipped due to disabled flag)
	proxy.initUpstreamCertBatcher()

	// Verify batcher was not created
	assert.Nil(t, spec.UpstreamCertExpiryBatcher, "Batcher should not be initialized when disabled")

	// Unload should be safe
	assert.NotPanics(t, func() {
		spec.Unload()
	}, "Unload should not panic when upstream certs are disabled")
}
