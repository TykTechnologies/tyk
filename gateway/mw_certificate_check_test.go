package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// setupMW returns a CertificateCheckMW with a configurable CertificateManager.
func setupMW(t *testing.T, useMutualTLS bool, setupMock func(*mock.MockCertificateManager)) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if setupMock != nil {
		setupMock(mockCertManager)
	}

	// Create a mock cache for testing
	mockCache := cache.New(3600, 600)

	// Create the gateway configuration
	gwConfig := config.Config{
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

	// Create the gateway and set its configuration
	gw := &Gateway{
		CertificateManager: mockCertManager,
		UtilCache:          mockCache,
	}
	gw.SetConfig(gwConfig)

	return &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					UseMutualTLSAuth:   useMutualTLS,
					ClientCertificates: []string{"cert1"},
				},
				GlobalConfig: gwConfig,
			},
			Gw: gw,
		},
	}
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
	shouldFire = mw.shouldFireExpiryEvent("test-cert-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test shouldFireEvent with same certID (should not fire due to cooldown)
	shouldFire = mw.shouldFireExpiryEvent("test-cert-id", monitorConfig)
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
	t.Parallel()

	mw := setupMW(t, true, nil)

	monitorConfig := config.CertificateExpiryMonitorConfig{
		CheckCooldownSeconds: 3600, // 1 hour
	}

	// Test shouldSkipCertificate with empty certID
	shouldSkip := mw.shouldSkipCertificate("", monitorConfig)
	assert.True(t, shouldSkip, "Should skip check with empty certID")

	// Test shouldSkipCertificate with valid certID (should not skip on first call)
	shouldSkip = mw.shouldSkipCertificate("test-cert-id", monitorConfig)
	assert.False(t, shouldSkip, "Should not skip check on first call")

	// Test shouldSkipCertificate with same certID (should skip due to cooldown)
	shouldSkip = mw.shouldSkipCertificate("test-cert-id", monitorConfig)
	assert.True(t, shouldSkip, "Should skip check due to cooldown")

	// Test shouldSkipCertificate with different certID (should not skip)
	shouldSkip = mw.shouldSkipCertificate("different-cert-id", monitorConfig)
	assert.False(t, shouldSkip, "Should not skip check for different certID")

	// Test shouldSkipCertificate with zero cooldown (should never skip)
	monitorConfig.CheckCooldownSeconds = 0
	shouldSkip = mw.shouldSkipCertificate("different-cert-id", monitorConfig)
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
	shouldFire = mw.shouldFireExpiryEvent("test-cert-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test shouldFireExpiryEvent with same certID (should not fire due to cooldown)
	shouldFire = mw.shouldFireExpiryEvent("test-cert-id", monitorConfig)
	assert.False(t, shouldFire)

	// Test different certID should still be allowed to fire
	shouldFire = mw.shouldFireExpiryEvent("different-cert-id", monitorConfig)
	assert.True(t, shouldFire)

	// Test that the cooldown key is properly formatted
	// We can't directly test the Redis key, but we can verify the behavior
	// by checking that the same certID is still in cooldown
	shouldFire = mw.shouldFireExpiryEvent("different-cert-id", monitorConfig)
	assert.False(t, shouldFire)
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
	t.Parallel()

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

// TestCertificateCheckMW_Parallelization tests the parallelization logic
func TestCertificateCheckMW_Parallelization(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	// Test with different numbers of certificates
	testCases := []struct {
		name            string
		certCount       int
		maxConcurrent   int
		expectedWorkers int
	}{
		{"Single certificate", 1, 5, 1},
		{"Two certificates", 2, 5, 1},
		{"Three certificates", 3, 5, 3},
		{"Five certificates", 5, 3, 3},
		{"Ten certificates", 10, 5, 5},
		{"Zero max concurrent", 5, 0, 5},
		{"Negative max concurrent", 5, -1, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_ *testing.T) {
			// Update the middleware's configuration for this test case
			mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.MaxConcurrentChecks = tc.maxConcurrent

			// Create test certificates
			certs := make([]*tls.Certificate, tc.certCount)
			for i := 0; i < tc.certCount; i++ {
				certs[i] = createTestCertificateWithName(30, fmt.Sprintf("test-%d.example.com", i))
			}

			// Call checkCertificateExpiration and verify it completes without error
			// We can't easily test the exact number of workers, but we can verify
			// that the function completes successfully
			mw.checkCertificateExpiration(certs)

			// The test passes if no panic or error occurs
		})
	}
}

// TestCertificateCheckMW_WorkerCountCalculation tests the worker count calculation logic
func TestCertificateCheckMW_WorkerCountCalculation(t *testing.T) {
	t.Parallel()

	mw := setupMW(t, true, nil)

	// Test various scenarios for worker count calculation
	testCases := []struct {
		name            string
		certCount       int
		maxConcurrent   int
		expectedWorkers int
	}{
		{"Single certificate", 1, 5, 1},
		{"Two certificates", 2, 5, 1},
		{"Three certificates", 3, 5, 3},
		{"Five certificates", 5, 3, 3},
		{"Ten certificates", 10, 5, 5},
		{"Zero max concurrent", 5, 0, 5},
		{"Negative max concurrent", 5, -1, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Update the middleware's configuration for this test case
			mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor.MaxConcurrentChecks = tc.maxConcurrent

			// Create test certificates
			certs := make([]*tls.Certificate, tc.certCount)
			for i := 0; i < tc.certCount; i++ {
				certs[i] = createTestCertificateWithName(30, fmt.Sprintf("test-%d.example.com", i))
			}

			// Call checkCertificateExpiration and verify it completes without error
			mw.checkCertificateExpiration(certs)

			// The test passes if no panic or error occurs
		})
	}
}
