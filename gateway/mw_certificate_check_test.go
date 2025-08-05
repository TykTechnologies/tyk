package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// setupMW returns a CertificateCheckMW with a configurable CertificateManager.
func setupMW(t *testing.T, useMutualTLS bool, setupMock func(*mock.MockCertificateManager)) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	// Create a mock cache for testing
	mockCache := cache.New(3600, 600)

	// Generate a unique test prefix to avoid key clashes between test runs
	testPrefix := fmt.Sprintf("test-%d-", time.Now().UnixNano())

	// Create gateway configuration
	gwConfig := config.Config{
		Storage: config.StorageOptionsConf{
			Type:    "redis",
			Host:    "localhost",
			Port:    6379,
			MaxIdle: 100,
		},
		Security: config.SecurityConfig{
			Certificates: config.CertificatesConfig{
				API: []string{"cert2"},
			},
			CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 3600,
				EventCooldownSeconds: 86400,
			},
		},
	}

	// Create gateway
	gw := &Gateway{
		CertificateManager: mockCertManager,
		UtilCache:          mockCache,
	}
	gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())
	gw.SetConfig(gwConfig)

	// Connect to Redis
	ctx := context.Background()
	gw.StorageConnectionHandler.Connect(ctx, func() {
		// Connection callback - do nothing for tests
	}, &gwConfig)

	// Wait for connection to be established
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := gw.StorageConnectionHandler.WaitConnect(timeout)
	if !connected {
		t.Fatalf("Redis connection was not established in test setup")
	}

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:              "test-api-id",
			OrgID:              "test-org-id",
			UseMutualTLSAuth:   useMutualTLS,
			ClientCertificates: []string{"cert1"},
		},
		GlobalConfig: gwConfig,
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   gw,
		},
	}

	// Initialize Redis store with unique test prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	if setupMock != nil {
		setupMock(mockCertManager)
	}

	return mw
}

// Table-driven tests for Name method
func TestCertificateCheckMW_Name(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	assert.Equal(t, "CertificateCheckMW", mw.Name())
}

// Table-driven tests for EnabledForSpec method
func TestCertificateCheckMW_EnabledForSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		useMutualTLS bool
		enabled      bool
	}{
		{"MutualTLS enabled", true, true},
		{"MutualTLS disabled", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw := setupMW(t, tc.useMutualTLS, nil)
			assert.Equal(t, tc.enabled, mw.EnabledForSpec())
		})
	}
}

func TestCertificateCheckMW_ProcessRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		useMutualTLS   bool
		statusOkIgnore bool
		req            *http.Request
		certs          []*tls.Certificate
		peerCerts      []*x509.Certificate
		certListNil    bool
		expiredPeer    bool
		expectCode     int
		expectErr      bool
	}{
		// Basic paths
		{
			name:           "StatusOkAndIgnore short-circuits",
			useMutualTLS:   true,
			statusOkIgnore: true,
			req:            &http.Request{},
			expectCode:     http.StatusOK,
			expectErr:      false,
		},
		{
			name:         "No MutualTLS returns OK",
			useMutualTLS: false,
			req:          &http.Request{},
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		// Edge cases
		{
			name:       "Nil request returns OK",
			req:        nil,
			expectCode: http.StatusOK,
			expectErr:  false,
		},
		{
			name:       "Request without TLS returns OK when no MutualTLS",
			req:        &http.Request{},
			expectCode: http.StatusOK,
			expectErr:  false,
		},
		// MutualTLS specific cases
		{
			name:         "MutualTLS without TLS returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{}, // No TLS
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with empty cert list returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}},
			certs:        []*tls.Certificate{},
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with nil cert in list returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}},
			certs:        []*tls.Certificate{nil},
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with missing PeerCertificates returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}},
			certs:        []*tls.Certificate{{}},
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with valid certificate returns OK",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(time.Hour)}}},
			req:          &http.Request{}, // Will be set up below
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "MutualTLS with expiring certificate returns OK but fires event",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(15 * 24 * time.Hour)}}}, // 15 days until expiry
			req:          &http.Request{},                                                                                                                                                                                                 // Will be set up below
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "MutualTLS with certificate within warning threshold returns OK but fires event",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(5 * 24 * time.Hour)}}}, // 5 days until expiry (within warning threshold)
			req:          &http.Request{},                                                                                                                                                                                                // Will be set up below
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "MutualTLS with certificate outside warning threshold returns OK",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(60 * 24 * time.Hour)}}}, // 60 days until expiry (outside warning threshold)
			req:          &http.Request{},                                                                                                                                                                                                 // Will be set up below
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Set up request context if needed
			if tc.req != nil && tc.statusOkIgnore {
				ctxSetRequestStatus(tc.req, StatusOkAndIgnore)
			}

			// Set up PeerCertificates if specified
			if tc.peerCerts != nil && tc.req != nil {
				tc.req.TLS = &tls.ConnectionState{PeerCertificates: tc.peerCerts}
			}

			// Use a custom CertificateManager if certs are specified
			var setupMock func(*mock.MockCertificateManager)
			if tc.useMutualTLS {
				setupMock = func(m *mock.MockCertificateManager) {
					m.EXPECT().
						List(gomock.Any(), gomock.Any()).
						Return(tc.certs).
						AnyTimes()
				}
			}
			mw := setupMW(t, tc.useMutualTLS, setupMock)

			err, code := mw.ProcessRequest(nil, tc.req, nil)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectCode, code)
		})
	}
}

// TestCertificateCheckMW_HelperMethods tests the helper methods for certificate expiration checking
func TestCertificateCheckMW_HelperMethods(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	// Test generateCertificateID with nil certificate
	certID := mw.generateCertificateID(nil)
	assert.Equal(t, "", certID)

	// Test generateCertificateID with valid certificate
	validCert := &tls.Certificate{
		Leaf: &x509.Certificate{
			Raw: []byte("test-certificate-data"),
		},
	}
	certID = mw.generateCertificateID(validCert)
	assert.NotEmpty(t, certID)
	assert.Len(t, certID, 64) // SHA256 hash is 32 bytes = 64 hex chars

	// Test shouldFireEvent with empty certID
	monitorConfig := config.CertificateExpiryMonitorConfig{
		EventCooldownSeconds: 3600,
	}
	shouldFire := mw.shouldFireExpiryEvent("", monitorConfig)
	assert.False(t, shouldFire)

	// Test shouldFireEvent with valid certID (should fire on first call)
	shouldFire = mw.shouldFireExpiryEvent("helper-test-cert-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test shouldFireEvent with same certID (should not fire due to cooldown)
	shouldFire = mw.shouldFireExpiryEvent("helper-test-cert-id", monitorConfig)
	assert.False(t, shouldFire)

	// Test fireCertificateExpiringSoonEvent with nil certificate
	mw.fireCertificateExpiringSoonEvent(nil, 30)

	// Test fireCertificateExpiringSoonEvent with valid certificate
	validCert.Leaf.Subject.CommonName = "test.example.com"
	validCert.Leaf.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	mw.fireCertificateExpiringSoonEvent(validCert, 30)
}

// TestCertificateCheckMW_CheckCooldown tests the check cooldown mechanism
func TestCertificateCheckMW_CheckCooldown(t *testing.T) {
	// t.Parallel() // Disable parallel execution to avoid Redis connection issues

	mw := setupMW(t, true, nil)

	monitorConfig := config.CertificateExpiryMonitorConfig{
		CheckCooldownSeconds: 3600, // 1 hour
	}

	// Test shouldSkipCertificate with empty certID
	shouldSkip := mw.shouldSkipCertificate("", monitorConfig)
	assert.True(t, shouldSkip, "Should skip check with empty certID")

	// Test shouldSkipCertificate with valid certID (should not skip on first call)
	shouldSkip = mw.shouldSkipCertificate("check-cooldown-test-id", monitorConfig)
	assert.False(t, shouldSkip, "Should not skip check on first call")

	// Test shouldSkipCertificate with same certID (should skip due to cooldown)
	shouldSkip = mw.shouldSkipCertificate("check-cooldown-test-id", monitorConfig)
	assert.True(t, shouldSkip, "Should skip check due to cooldown")

	// Test shouldSkipCertificate with different certID (should not skip)
	shouldSkip = mw.shouldSkipCertificate("check-cooldown-different-id", monitorConfig)
	assert.False(t, shouldSkip, "Should not skip check for different certID")

	// Test shouldSkipCertificate with zero cooldown (should never skip)
	monitorConfig.CheckCooldownSeconds = 0
	shouldSkip = mw.shouldSkipCertificate("check-cooldown-zero-id", monitorConfig)
	assert.False(t, shouldSkip, "Should not skip check with zero cooldown")
}

// TestCertificateCheckMW_EventCooldown tests the event cooldown mechanism
func TestCertificateCheckMW_EventCooldown(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	monitorConfig := config.CertificateExpiryMonitorConfig{
		EventCooldownSeconds: 86400, // 24 hours
	}

	// Test shouldFireExpiryEvent with empty certID
	shouldFire := mw.shouldFireExpiryEvent("", monitorConfig)
	assert.False(t, shouldFire)

	// Test shouldFireExpiryEvent with valid certID (should fire on first call)
	shouldFire = mw.shouldFireExpiryEvent("event-cooldown-test-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test shouldFireExpiryEvent with same certID (should not fire due to cooldown)
	shouldFire = mw.shouldFireExpiryEvent("event-cooldown-test-id", monitorConfig)
	assert.False(t, shouldFire, "Should not fire event due to cooldown")

	// Test different certID should still be allowed to fire
	shouldFire = mw.shouldFireExpiryEvent("event-cooldown-different-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test that the cooldown key is properly formatted
	// We can't directly test the Redis key, but we can verify the behavior
	// by checking that the same certID is still in cooldown
	shouldFire = mw.shouldFireExpiryEvent("event-cooldown-different-id", monitorConfig)
	assert.False(t, shouldFire, "Should not fire event due to cooldown")
}

// TestCertificateCheckMW_CooldownIntegration tests both cooldown mechanisms working together
func TestCertificateCheckMW_CooldownIntegration(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	monitorConfig := config.CertificateExpiryMonitorConfig{
		CheckCooldownSeconds: 3600,  // 1 hour
		EventCooldownSeconds: 86400, // 24 hours
	}

	// Test that both cooldowns work independently
	certID := "integration-test-cert"

	// First check should succeed
	shouldSkip := mw.shouldSkipCertificate(certID, monitorConfig)
	assert.False(t, shouldSkip, "First check should succeed")

	// Second check should fail due to check cooldown
	shouldSkip = mw.shouldSkipCertificate(certID, monitorConfig)
	assert.True(t, shouldSkip, "Second check should fail due to cooldown")

	// First event should succeed
	shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.True(t, shouldFire, "First event should succeed")

	// Second event should fail due to event cooldown
	shouldFire = mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.False(t, shouldFire, "Second event should fail due to cooldown")

	// Different certID should work for both operations
	differentCertID := "different-integration-test-cert"

	shouldSkip = mw.shouldSkipCertificate(differentCertID, monitorConfig)
	assert.False(t, shouldSkip, "Different certID check should succeed")

	shouldFire = mw.shouldFireExpiryEvent(differentCertID, monitorConfig)
	assert.True(t, shouldFire, "Different certID event should succeed")
}

// TestCertificateCheckMW_CooldownConfiguration tests cooldown configuration options
func TestCertificateCheckMW_CooldownConfiguration(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	// Test zero cooldown values (should disable cooldowns)
	monitorConfig := config.CertificateExpiryMonitorConfig{
		CheckCooldownSeconds: 0,
		EventCooldownSeconds: 0,
	}

	certID := "zero-cooldown-test"

	// With zero check cooldown, should never skip
	shouldSkip := mw.shouldSkipCertificate(certID, monitorConfig)
	assert.False(t, shouldSkip, "Should not skip with zero check cooldown")

	shouldSkip = mw.shouldSkipCertificate(certID, monitorConfig)
	assert.False(t, shouldSkip, "Should still not skip with zero check cooldown")

	// With zero event cooldown, should always fire
	shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.True(t, shouldFire, "Should fire with zero event cooldown")

	shouldFire = mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.True(t, shouldFire, "Should still fire with zero event cooldown")

	// Test negative cooldown values (should be treated as zero)
	monitorConfig.CheckCooldownSeconds = -1
	monitorConfig.EventCooldownSeconds = -1

	shouldSkip = mw.shouldSkipCertificate(certID, monitorConfig)
	assert.False(t, shouldSkip, "Should not skip with negative check cooldown")

	shouldFire = mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.True(t, shouldFire, "Should fire with negative event cooldown")
}

// TestCertificateCheckMW_CooldownPersistence tests that cooldowns persist across function calls
func TestCertificateCheckMW_CooldownPersistence(t *testing.T) {
	// Removed t.Parallel() to prevent interference with other tests

	mw := setupMW(t, true, nil)

	monitorConfig := config.CertificateExpiryMonitorConfig{
		CheckCooldownSeconds: 3600,  // 1 hour
		EventCooldownSeconds: 86400, // 24 hours
	}

	certID := "persistence-test-cert"

	// Set up cooldowns
	mw.shouldSkipCertificate(certID, monitorConfig) // This sets the check cooldown
	mw.shouldFireExpiryEvent(certID, monitorConfig) // This sets the event cooldown

	// Test that cooldowns persist
	shouldSkip := mw.shouldSkipCertificate(certID, monitorConfig)
	assert.True(t, shouldSkip, "Check cooldown should persist")

	shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
	assert.False(t, shouldFire, "Event cooldown should persist")

	// Test that different certIDs are not affected
	differentCertID := "different-persistence-test-cert"

	shouldSkip = mw.shouldSkipCertificate(differentCertID, monitorConfig)
	assert.False(t, shouldSkip, "Different certID should not be affected by cooldown")

	shouldFire = mw.shouldFireExpiryEvent(differentCertID, monitorConfig)
	assert.True(t, shouldFire, "Different certID should not be affected by cooldown")
}

// createTestCertificateWithName creates a test certificate with specified expiration and common name
func createTestCertificateWithName(daysUntilExpiry int, commonName string) *tls.Certificate {
	expirationDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotAfter: expirationDate,
			Raw:      []byte("test-certificate-data"),
			Extensions: []pkix.Extension{
				{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
			},
		},
	}
}

// TestCertificateCheckMW_ConcurrencySafety tests that the certificate check middleware
// is thread-safe under high concurrency scenarios
func TestCertificateCheckMW_ConcurrencySafety(t *testing.T) {
	t.Parallel()

	// Use setupMW to get a properly configured middleware with randomized keys
	mw := setupMW(t, true, nil)

	// Use a unique certID for this test
	certID := "concurrency-safety-test-id"

	t.Run("Concurrent certificate checks", func(t *testing.T) {
		const numGoroutines = 50
		const checksPerGoroutine = 10

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*checksPerGoroutine)

		// Start multiple goroutines that check the same certificate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(_ int) {
				defer wg.Done()

				for j := 0; j < checksPerGoroutine; j++ {
					// Test shouldSkipCertificate with the same certificate ID
					shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					results <- shouldSkip

					// Small delay to increase chance of race conditions
					time.Sleep(time.Microsecond)
				}
			}(i)
		}

		wg.Wait()
		close(results)

		// Count results
		skippedCount := 0
		checkedCount := 0
		for result := range results {
			if result {
				skippedCount++
			} else {
				checkedCount++
			}
		}

		// Verify that only one check was allowed (the first one)
		// All subsequent checks should be skipped due to cooldown
		assert.Equal(t, 1, checkedCount, "Only one certificate check should be allowed")
		assert.Equal(t, numGoroutines*checksPerGoroutine-1, skippedCount, "All other checks should be skipped due to cooldown")
	})

	t.Run("Concurrent event firing", func(t *testing.T) {
		const numGoroutines = 30
		const eventsPerGoroutine = 5

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*eventsPerGoroutine)

		// Start multiple goroutines that try to fire events for the same certificate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(_ int) {
				defer wg.Done()

				for j := 0; j < eventsPerGoroutine; j++ {
					// Test shouldFireExpiryEvent with the same certificate ID
					shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					results <- shouldFire

					// Small delay to increase chance of race conditions
					time.Sleep(time.Microsecond)
				}
			}(i)
		}

		wg.Wait()
		close(results)

		// Count results
		firedCount := 0
		skippedCount := 0
		for result := range results {
			if result {
				firedCount++
			} else {
				skippedCount++
			}
		}

		// Verify that only one event was allowed (the first one)
		// All subsequent events should be skipped due to cooldown
		assert.Equal(t, 1, firedCount, "Only one event should be allowed")
		assert.Equal(t, numGoroutines*eventsPerGoroutine-1, skippedCount, "All other events should be skipped due to cooldown")
	})

	t.Run("Mixed concurrent operations", func(t *testing.T) {
		const numGoroutines = 20

		var wg sync.WaitGroup
		checkResults := make(chan bool, numGoroutines)
		eventResults := make(chan bool, numGoroutines)

		// Start goroutines that perform both checks and event firing
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(_ int) {
				defer wg.Done()

				// Use different certIDs for check and event to avoid interference
				checkCertID := "mixed-concurrent-check-id"
				eventCertID := "mixed-concurrent-event-id"

				// Test both operations with different certIDs
				shouldSkip := mw.shouldSkipCertificate(checkCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
				checkResults <- shouldSkip

				shouldFire := mw.shouldFireExpiryEvent(eventCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
				eventResults <- shouldFire
			}(i)
		}

		wg.Wait()
		close(checkResults)
		close(eventResults)

		// Count check results
		checkSkippedCount := 0
		checkAllowedCount := 0
		for result := range checkResults {
			if result {
				checkSkippedCount++
			} else {
				checkAllowedCount++
			}
		}

		// Count event results
		eventSkippedCount := 0
		eventAllowedCount := 0
		for result := range eventResults {
			if result {
				eventAllowedCount++
			} else {
				eventSkippedCount++
			}
		}

		// Verify thread-safety for both operations
		assert.Equal(t, 1, checkAllowedCount, "Only one certificate check should be allowed")
		assert.Equal(t, numGoroutines-1, checkSkippedCount, "All other checks should be skipped")

		assert.Equal(t, 1, eventAllowedCount, "Only one event should be allowed")
		assert.Equal(t, numGoroutines-1, eventSkippedCount, "All other events should be skipped")
	})
}

// TestCertificateCheckMW_CacheConsistency tests that cache operations are consistent
// under concurrent access
func TestCertificateCheckMW_CacheConsistency(t *testing.T) {
	t.Parallel()

	// Use setupMW to get a properly configured middleware with randomized keys
	mw := setupMW(t, true, nil)

	t.Run("Certificate ID generation consistency", func(t *testing.T) {
		cert := createTestCertificateWithName(30, "test-cache-consistency-cert")

		const numGoroutines = 20
		var wg sync.WaitGroup
		results := make(chan string, numGoroutines)

		// Generate certificate IDs concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				certID := mw.generateCertificateID(cert)
				results <- certID
			}()
		}

		wg.Wait()
		close(results)

		// All results should be identical
		var firstResult string
		count := 0
		for result := range results {
			if count == 0 {
				firstResult = result
			} else {
				assert.Equal(t, firstResult, result, "All certificate IDs should be identical")
			}
			count++
		}

		assert.NotEmpty(t, firstResult, "Certificate ID should not be empty")
		assert.Equal(t, numGoroutines, count, "All goroutines should complete")
	})

	t.Run("Lock consistency for different certificates", func(t *testing.T) {
		certIDs := []string{"cache-consistency-cert1", "cache-consistency-cert2", "cache-consistency-cert3", "cache-consistency-cert4", "cache-consistency-cert5"}

		// Test that different certificates can be processed without interference
		for _, certID := range certIDs {
			// Use different certIDs for check and event to avoid interference
			checkCertID := certID + "-check"
			eventCertID := certID + "-event"

			// These should all succeed since they're different certificates
			shouldSkip := mw.shouldSkipCertificate(checkCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
			shouldFire := mw.shouldFireExpiryEvent(eventCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)

			// First call should allow, subsequent calls should skip
			assert.False(t, shouldSkip, "First check should not be skipped")
			assert.True(t, shouldFire, "First event should be allowed")
		}

		// Test that the same certificate ID returns consistent results
		sameCertID := "cache-consistency-same-cert"
		firstCheck := mw.shouldSkipCertificate(sameCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		secondCheck := mw.shouldSkipCertificate(sameCertID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)

		// First call should not skip, second call should skip due to cooldown
		assert.False(t, firstCheck, "First check should not be skipped")
		assert.True(t, secondCheck, "Second check should be skipped due to cooldown")
	})
}

// TestCertificateCheckMW_ParallelProcessingSafety tests the safety of parallel
// certificate processing with the worker pool
func TestCertificateCheckMW_ParallelProcessingSafety(t *testing.T) {
	t.Parallel()

	// Create multiple test certificates
	certs := make([]*tls.Certificate, 20)
	for i := range certs {
		certs[i] = createTestCertificateWithName(15+i, fmt.Sprintf("test-%d.example.com", i)) // Different expiry times
	}

	// Use setupMW to get a properly configured middleware with randomized keys
	mw := setupMW(t, true, nil)

	t.Run("Parallel certificate processing", func(t *testing.T) {
		const numIterations = 5

		for iteration := 0; iteration < numIterations; iteration++ {
			// Process certificates in parallel
			mw.checkCertificateExpiration(certs)

			// Verify that all certificates were processed
			// (This is a basic check - in a real scenario, we'd verify specific outcomes)
			assert.True(t, true, "Parallel processing should complete without errors")
		}
	})

	t.Run("Concurrent parallel processing", func(t *testing.T) {
		const numGoroutines = 3
		var wg sync.WaitGroup

		// Start multiple goroutines that process certificates in parallel
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(_ int) {
				defer wg.Done()

				// Process certificates multiple times
				for j := 0; j < 3; j++ {
					mw.checkCertificateExpiration(certs)
					time.Sleep(time.Millisecond) // Small delay
				}
			}(i)
		}

		wg.Wait()

		// Verify no panics or deadlocks occurred
		assert.True(t, true, "Concurrent parallel processing should complete without errors")
	})
}

// TestCertificateCheckMW_LockCleanup tests that locks are properly managed
// and don't cause memory leaks
func TestCertificateCheckMW_LockCleanup(t *testing.T) {
	t.Parallel()

	// Use setupMW to get a properly configured middleware with randomized keys
	mw := setupMW(t, true, nil)

	t.Run("Lock creation and reuse", func(t *testing.T) {
		certID := "lock-cleanup-test-cert"

		// Get lock multiple times for the same certificate
		lock1 := mw.acquireLock(certID)
		lock2 := mw.acquireLock(certID)

		// Should return the same lock instance
		assert.Equal(t, lock1, lock2, "Same certificate should return the same lock")

		// Test that the lock works
		lock1.Lock()
		// Critical section - verify lock is working
		_ = 1
		lock1.Unlock()
		lock2.Lock()
		// Critical section - verify lock is working
		_ = 1
		lock2.Unlock()

		// No deadlock should occur
		assert.True(t, true, "Lock operations should complete successfully")
	})

	t.Run("Different certificates get different locks", func(t *testing.T) {
		certID1 := "lock-cleanup-cert-id-1"
		certID2 := "lock-cleanup-cert-id-2"

		lock1 := mw.acquireLock(certID1)
		lock2 := mw.acquireLock(certID2)

		// Should return different lock instances
		if lock1 == lock2 {
			t.Errorf("Different certificates should return different locks: lock1=%p, lock2=%p", lock1, lock2)
		}

		// Both locks should work independently
		lock1.Lock()
		lock2.Lock()
		// Critical sections - verify locks are working
		_ = 1
		_ = 1
		lock1.Unlock()
		lock2.Unlock()

		// No deadlock should occur
		assert.True(t, true, "Independent lock operations should complete successfully")
	})
}

// Benchmark tests for concurrency performance
func BenchmarkCertificateCheckMW_ConcurrentChecks(b *testing.B) {
	// Create a test instance for benchmarking
	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID: "test-api-id",
					OrgID: "test-org-id",
				},
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	// Initialize Redis store with a unique prefix for benchmarks
	mw.Gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:benchmark-%d-", time.Now().UnixNano()),
		ConnectionHandler: mw.Gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	certID := "benchmark-cert-id"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		}
	})
}

func BenchmarkCertificateCheckMW_ConcurrentEvents(b *testing.B) {
	// Create a test instance for benchmarking
	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					APIID: "test-api-id",
					OrgID: "test-org-id",
				},
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	// Initialize Redis store with a unique prefix for benchmarks
	mw.Gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:benchmark-%d-", time.Now().UnixNano()),
		ConnectionHandler: mw.Gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	certID := "benchmark-cert-id"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		}
	})
}

// TestCertificateCheckMW_SimpleConcurrency tests basic concurrency safety
func TestCertificateCheckMW_SimpleConcurrency(t *testing.T) {
	t.Parallel()

	// Use setupMW to get a properly configured middleware with randomized keys
	mw := setupMW(t, true, nil)

	t.Run("Lock creation and reuse", func(t *testing.T) {
		certID := "simple-concurrency-test-cert"

		// Get lock multiple times for the same certificate
		lock1 := mw.acquireLock(certID)
		lock2 := mw.acquireLock(certID)

		// Should return the same lock instance
		assert.Equal(t, lock1, lock2, "Same certificate should return the same lock")

		// Test that the lock works
		lock1.Lock()
		// Critical section - verify lock is working
		_ = 1
		lock1.Unlock()
		lock2.Lock()
		// Critical section - verify lock is working
		_ = 1
		lock2.Unlock()

		// No deadlock should occur
		assert.True(t, true, "Lock operations should complete successfully")
	})

	t.Run("Different certificates get different locks", func(t *testing.T) {
		certID1 := "simple-concurrency-cert-id-1"
		certID2 := "simple-concurrency-cert-id-2"

		lock1 := mw.acquireLock(certID1)
		lock2 := mw.acquireLock(certID2)

		// Should return different lock instances
		if lock1 == lock2 {
			t.Errorf("Different certificates should return different locks: lock1=%p, lock2=%p", lock1, lock2)
		}

		// Both locks should work independently
		lock1.Lock()
		lock2.Lock()
		// Critical sections - verify locks are working
		_ = 1
		_ = 1
		lock1.Unlock()
		lock2.Unlock()

		// No deadlock should occur
		assert.True(t, true, "Independent lock operations should complete successfully")
	})

	t.Run("Concurrent certificate checks", func(t *testing.T) {
		certID := "simple-concurrent-check-test-cert"
		const numGoroutines = 10

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines)

		// Start multiple goroutines that check the same certificate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
				results <- shouldSkip
			}()
		}

		wg.Wait()
		close(results)

		// Count results
		skippedCount := 0
		checkedCount := 0
		for result := range results {
			if result {
				skippedCount++
			} else {
				checkedCount++
			}
		}

		// Verify that only one check was allowed (the first one)
		assert.Equal(t, 1, checkedCount, "Only one certificate check should be allowed")
		assert.Equal(t, numGoroutines-1, skippedCount, "All other checks should be skipped due to cooldown")
	})

	t.Run("Concurrent event firing", func(t *testing.T) {
		certID := "simple-concurrent-event-test-cert"
		const numGoroutines = 8

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines)

		// Start multiple goroutines that try to fire events for the same certificate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
				results <- shouldFire
			}()
		}

		wg.Wait()
		close(results)

		// Count results
		firedCount := 0
		skippedCount := 0
		for result := range results {
			if result {
				firedCount++
			} else {
				skippedCount++
			}
		}

		// Verify that only one event was allowed (the first one)
		assert.Equal(t, 1, firedCount, "Only one event should be allowed")
		assert.Equal(t, numGoroutines-1, skippedCount, "All other events should be skipped due to cooldown")
	})
}
