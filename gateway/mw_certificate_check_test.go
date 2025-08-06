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
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// createTestCertificate creates a test certificate with specified expiration and common name
func createTestCertificate(daysUntilExpiry int, commonName string) *tls.Certificate {
	expirationDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotAfter: expirationDate,
			Raw:      []byte("test-certificate-data-" + commonName),
			Extensions: []pkix.Extension{
				{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
			},
		},
	}
}

// setupCertificateCheckMW returns a CertificateCheckMW with a configurable CertificateManager.
func setupCertificateCheckMW(t *testing.T, useMutualTLS bool, setupMock func(*mock.MockCertificateManager)) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

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

	mw := setupCertificateCheckMW(t, true, nil)
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
			mw := setupCertificateCheckMW(t, tc.useMutualTLS, nil)
			assert.Equal(t, tc.enabled, mw.EnabledForSpec())
		})
	}
}

// Comprehensive table-driven test for ProcessRequest method
func TestCertificateCheckMW_ProcessRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		useMutualTLS   bool
		statusOkIgnore bool
		req            *http.Request
		certs          []*tls.Certificate
		peerCerts      []*x509.Certificate
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
			name:         "MutualTLS with valid certificate returns OK",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(time.Hour)}}},
			req:          &http.Request{},
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "MutualTLS with expiring certificate returns OK but fires event",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(15 * 24 * time.Hour)}}},
			req:          &http.Request{},
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
			mw := setupCertificateCheckMW(t, tc.useMutualTLS, setupMock)

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

// Test helper methods for certificate expiration checking
func TestCertificateCheckMW_HelperMethods(t *testing.T) {
	t.Parallel()

	mw := setupCertificateCheckMW(t, true, nil)

	// Test generateCertificateID with nil certificate
	certID := mw.computeCertID(nil)
	assert.Equal(t, "", certID)

	// Test generateCertificateID with valid certificate
	validCert := &tls.Certificate{
		Leaf: &x509.Certificate{
			Raw: []byte("test-certificate-data"),
		},
	}
	certID = mw.computeCertID(validCert)
	assert.NotEmpty(t, certID)
	assert.Len(t, certID, 64) // SHA256 hash is 32 bytes = 64 hex chars

	// Test shouldFireEvent with valid certID
	monitorConfig := config.CertificateExpiryMonitorConfig{
		EventCooldownSeconds: 3600,
	}
	shouldFire := mw.shouldFireExpiryEvent("helper-test-cert-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test shouldFireEvent with same certID (should not fire due to cooldown)
	shouldFire = mw.shouldFireExpiryEvent("helper-test-cert-id", monitorConfig)
	assert.False(t, shouldFire)

	// Test fireCertificateExpiringSoonEvent with valid certificate
	validCert.Leaf.Subject.CommonName = "test.example.com"
	validCert.Leaf.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	mw.fireCertificateExpiringSoonEvent(validCert, 30)
}

// Comprehensive test for all cooldown mechanisms
func TestCertificateCheckMW_CooldownMechanisms(t *testing.T) {
	t.Parallel()

	t.Run("Check Cooldown", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)
		monitorConfig := config.CertificateExpiryMonitorConfig{
			CheckCooldownSeconds: 3600, // 1 hour
		}

		// Test shouldSkipCertificate with valid certID (should not skip on first call)
		shouldSkip := mw.shouldCooldown(monitorConfig, "check-cooldown-test-id")
		assert.False(t, shouldSkip, "Should not skip check on first call")

		// Test shouldSkipCertificate with same certID (should skip due to cooldown)
		shouldSkip = mw.shouldCooldown(monitorConfig, "check-cooldown-test-id")
		assert.True(t, shouldSkip, "Should skip check due to cooldown")

		// Test shouldSkipCertificate with same certID (should skip due to cooldown)
		shouldSkip = mw.shouldCooldown(monitorConfig, "check-cooldown-test-id")
		assert.True(t, shouldSkip, "Should skip check due to cooldown")

		// Test shouldSkipCertificate with different certID (should not skip)
		shouldSkip = mw.shouldCooldown(monitorConfig, "check-cooldown-different-id")
		assert.False(t, shouldSkip, "Should not skip check for different certID")

		// Test shouldSkipCertificate with zero cooldown (should never skip)
		monitorConfig.CheckCooldownSeconds = 0
		shouldSkip = mw.shouldCooldown(monitorConfig, "check-cooldown-zero-id")
		assert.False(t, shouldSkip, "Should not skip check with zero cooldown")
	})

	t.Run("Event Cooldown", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)
		monitorConfig := config.CertificateExpiryMonitorConfig{
			EventCooldownSeconds: 86400, // 24 hours
		}

		// Test shouldFireExpiryEvent with valid certID (should fire on first call)
		shouldFire := mw.shouldFireExpiryEvent("event-cooldown-test-id", monitorConfig)
		assert.True(t, shouldFire)

		// Test shouldFireExpiryEvent with same certID (should not fire due to cooldown)
		shouldFire = mw.shouldFireExpiryEvent("event-cooldown-test-id", monitorConfig)
		assert.False(t, shouldFire, "Should not fire event due to cooldown")

		// Test different certID should still be allowed to fire
		shouldFire = mw.shouldFireExpiryEvent("event-cooldown-different-id", monitorConfig)
		assert.True(t, shouldFire)
	})

	t.Run("Cooldown Integration", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)
		monitorConfig := config.CertificateExpiryMonitorConfig{
			CheckCooldownSeconds: 3600,  // 1 hour
			EventCooldownSeconds: 86400, // 24 hours
		}

		// Test that both cooldowns work independently
		certID := "integration-test-cert"

		// First check should succeed
		shouldSkip := mw.shouldCooldown(monitorConfig, certID)
		assert.False(t, shouldSkip, "First check should succeed")

		// Second check should fail due to check cooldown
		shouldSkip = mw.shouldCooldown(monitorConfig, certID)
		assert.True(t, shouldSkip, "Second check should fail due to cooldown")

		// First event should succeed
		shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
		assert.True(t, shouldFire, "First event should succeed")

		// Second event should fail due to event cooldown
		shouldFire = mw.shouldFireExpiryEvent(certID, monitorConfig)
		assert.False(t, shouldFire, "Second event should fail due to cooldown")
	})

	t.Run("Cooldown Configuration", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)

		// Test zero cooldown values (should use defaults)
		monitorConfig := config.CertificateExpiryMonitorConfig{
			CheckCooldownSeconds: 0,
			EventCooldownSeconds: 0,
		}

		certID := "zero-cooldown-test"

		// With zero check cooldown, should use default (3600 seconds)
		shouldSkip := mw.shouldCooldown(monitorConfig, certID)
		assert.False(t, shouldSkip, "Should not skip on first check with zero cooldown (uses default)")

		shouldSkip = mw.shouldCooldown(monitorConfig, certID)
		assert.True(t, shouldSkip, "Should skip on second check with zero cooldown (uses default)")

		// With zero event cooldown, should use default (86400 seconds)
		shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
		assert.True(t, shouldFire, "Should fire on first event with zero cooldown (uses default)")

		shouldFire = mw.shouldFireExpiryEvent(certID, monitorConfig)
		assert.False(t, shouldFire, "Should not fire on second event with zero cooldown (uses default)")
	})

	t.Run("Cooldown Persistence", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)
		monitorConfig := config.CertificateExpiryMonitorConfig{
			CheckCooldownSeconds: 3600,  // 1 hour
			EventCooldownSeconds: 86400, // 24 hours
		}

		certID := "persistence-test-cert"

		// Set up cooldowns
		mw.shouldCooldown(monitorConfig, certID)        // This sets the check cooldown
		mw.shouldFireExpiryEvent(certID, monitorConfig) // This sets the event cooldown

		// Test that cooldowns persist
		shouldSkip := mw.shouldCooldown(monitorConfig, certID)
		assert.True(t, shouldSkip, "Check cooldown should persist")

		shouldFire := mw.shouldFireExpiryEvent(certID, monitorConfig)
		assert.False(t, shouldFire, "Event cooldown should persist")

		// Test that different certIDs are not affected
		differentCertID := "different-persistence-test-cert"

		shouldSkip = mw.shouldCooldown(monitorConfig, differentCertID)
		assert.False(t, shouldSkip, "Different certID should not be affected by cooldown")

		shouldFire = mw.shouldFireExpiryEvent(differentCertID, monitorConfig)
		assert.True(t, shouldFire, "Different certID should not be affected by cooldown")
	})
}

// Comprehensive test for all concurrency scenarios
func TestCertificateCheckMW_Concurrency(t *testing.T) {
	t.Parallel()

	t.Run("Concurrency Safety", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)
		certID := "concurrency-safety-test-id"

		// Test concurrent certificate checks
		const numGoroutines = 20
		const checksPerGoroutine = 5

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines*checksPerGoroutine)

		// Start multiple goroutines that check the same certificate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for j := 0; j < checksPerGoroutine; j++ {
					shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
					results <- shouldSkip
					time.Sleep(time.Microsecond)
				}
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
		assert.Equal(t, numGoroutines*checksPerGoroutine-1, skippedCount, "All other checks should be skipped due to cooldown")
	})

	t.Run("Cache Consistency", func(t *testing.T) {
		mw := setupCertificateCheckMW(t, true, nil)

		// Test certificate ID generation consistency
		cert := createTestCertificate(30, "test-cache-consistency-cert")

		const numGoroutines = 10
		var wg sync.WaitGroup
		results := make(chan string, numGoroutines)

		// Generate certificate IDs concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				certID := mw.computeCertID(cert)
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

	t.Run("Parallel Processing Safety", func(t *testing.T) {
		// Create multiple test certificates
		certs := make([]*tls.Certificate, 10)
		for i := range certs {
			certs[i] = createTestCertificate(15+i, fmt.Sprintf("test-%d.example.com", i))
		}

		mw := setupCertificateCheckMW(t, true, nil)

		// Test parallel certificate processing
		const numIterations = 3
		for iteration := 0; iteration < numIterations; iteration++ {
			mw.checkCertificatesExpiration(certs)
		}

		// Test concurrent parallel processing
		const numGoroutines = 2
		var wg sync.WaitGroup

		errorChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 2; j++ {
					// Capture any panics and convert to errors
					func() {
						defer func() {
							if r := recover(); r != nil {
								errorChan <- fmt.Errorf("panic in goroutine: %v", r)
							}
						}()
						mw.checkCertificatesExpiration(certs)
					}()
					time.Sleep(time.Millisecond)
				}
			}()
		}

		wg.Wait()
		close(errorChan)

		// Verify no errors occurred during concurrent processing
		for err := range errorChan {
			t.Errorf("Error during concurrent processing: %v", err)
		}

		// Verify that the middleware is still in a valid state after concurrent processing
		assert.NotNil(t, mw.store, "Store should remain initialized after concurrent processing")
		assert.NotNil(t, mw.Spec, "Spec should remain initialized after concurrent processing")
		assert.NotNil(t, mw.Gw, "Gateway should remain initialized after concurrent processing")

		// Test that certificate ID computation still works correctly after concurrent processing
		testCert := createTestCertificate(30, "post-concurrency-test")
		certID := mw.computeCertID(testCert)
		assert.NotEmpty(t, certID, "Certificate ID computation should still work after concurrent processing")

		// Test that cooldown mechanism still works correctly after concurrent processing
		shouldSkip := mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
		assert.False(t, shouldSkip, "First check should be allowed after concurrent processing")

		// Second check should be blocked by cooldown
		shouldSkip = mw.shouldCooldown(mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor, certID)
		assert.True(t, shouldSkip, "Second check should be blocked by cooldown after concurrent processing")
	})
}
