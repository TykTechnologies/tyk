package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/storage"
)

// baseMockStorage provides default implementations for all storage.Handler methods.
// Specific mocks can embed this and override only the methods they need.
type baseMockStorage struct{}

func (b *baseMockStorage) GetMultiKey(_ []string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (b *baseMockStorage) SetKey(_, _ string, _ int64) error {
	return nil
}

func (b *baseMockStorage) GetRawKey(key string) (string, error) {
	return "", errors.New("not implemented")
}

func (b *baseMockStorage) SetRawKey(_, _ string, _ int64) error {
	return nil
}

func (b *baseMockStorage) GetExp(_ string) (int64, error) {
	return -1, nil
}

func (b *baseMockStorage) SetExp(_ string, _ int64) error {
	return nil
}

func (b *baseMockStorage) DeleteKey(_ string) bool {
	return true
}

func (b *baseMockStorage) DeleteRawKey(_ string) bool {
	return true
}

func (b *baseMockStorage) DeleteRawKeys(_ []string) bool {
	return true
}

func (b *baseMockStorage) Connect() bool {
	return true
}

func (b *baseMockStorage) Exists(_ string) (bool, error) {
	return false, nil
}

func (b *baseMockStorage) GetKeys(_ string) []string {
	return []string{}
}

func (b *baseMockStorage) GetKeysAndValues() map[string]string {
	return map[string]string{}
}

func (b *baseMockStorage) GetKeysAndValuesWithFilter(_ string) map[string]string {
	return map[string]string{}
}

func (b *baseMockStorage) DeleteKeys(_ []string) bool {
	return true
}

func (b *baseMockStorage) Decrement(_ string) {}

func (b *baseMockStorage) IncrememntWithExpire(_ string, _ int64) int64 {
	return 0
}

func (b *baseMockStorage) SetRollingWindow(_ string, _ int64, _ string, _ bool) (int, []interface{}) {
	return 0, nil
}

func (b *baseMockStorage) GetRollingWindow(_ string, _ int64, _ bool) (int, []interface{}) {
	return 0, nil
}

func (b *baseMockStorage) GetSet(_ string) (map[string]string, error) {
	return nil, errors.New("not implemented")
}

func (b *baseMockStorage) AddToSet(_, _ string) {}

func (b *baseMockStorage) GetAndDeleteSet(_ string) []interface{} {
	return nil
}

func (b *baseMockStorage) RemoveFromSet(_, _ string) {}

func (b *baseMockStorage) DeleteScanMatch(_ string) bool {
	return true
}

func (b *baseMockStorage) DeleteAllKeys() bool {
	return true
}

func (b *baseMockStorage) GetKeyPrefix() string {
	return ""
}

func (b *baseMockStorage) AddToSortedSet(_, _ string, _ float64) {}

func (b *baseMockStorage) GetSortedSetRange(_, _, _ string) ([]string, []float64, error) {
	return nil, nil, errors.New("not implemented")
}

func (b *baseMockStorage) RemoveSortedSetRange(_, _, _ string) error {
	return errors.New("not implemented")
}

func (b *baseMockStorage) GetListRange(_ string, _, _ int64) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (b *baseMockStorage) RemoveFromList(_, _ string) error {
	return errors.New("not implemented")
}

func (b *baseMockStorage) AppendToSet(_, _ string) {}

// MockStorage simulates MDCB storage with configurable failure patterns
type MockStorage struct {
	baseMockStorage
	callCount  int
	certData   map[string]string
	t          *testing.T
	shouldFail func(attempt int) bool
}

// MockStorageOption configures a MockStorage
type MockStorageOption func(*MockStorage)

// NewMockStorage creates a new mock storage with the given certificate data and options
func NewMockStorage(t *testing.T, certData map[string]string, opts ...MockStorageOption) *MockStorage {
	m := &MockStorage{
		certData: certData,
		t:        t,
	}
	m.Apply(opts...)
	return m
}

// Apply applies one or more options to the mock
func (m *MockStorage) Apply(opts ...MockStorageOption) {
	for _, opt := range opts {
		opt(m)
	}
}

func (m *MockStorage) GetKey(key string) (string, error) {
	m.callCount++
	m.t.Logf("  [Attempt %d] GetKey called for: %s at %s",
		m.callCount, key, time.Now().Format("15:04:05.000"))

	if m.shouldFail != nil && m.shouldFail(m.callCount) {
		m.t.Logf("  [Attempt %d] FAIL: Returning ErrMDCBConnectionLost", m.callCount)
		return "", storage.ErrMDCBConnectionLost
	}

	// Look up certificate data by key
	// Keys come in as "raw-{certID}", so we look up the full key
	certData, exists := m.certData[key]
	if !exists {
		m.t.Logf("  [Attempt %d] Certificate not found for key: %s", m.callCount, key)
		return "", fmt.Errorf("certificate not found: %s", key)
	}

	m.t.Logf("  [Attempt %d] SUCCESS: Returning certificate", m.callCount)
	return certData, nil
}

func (m *MockStorage) GetRawKey(key string) (string, error) {
	return m.GetKey(key)
}

// WithFailFirst configures the mock to fail the first n attempts
func WithFailFirst(n int) MockStorageOption {
	return func(m *MockStorage) {
		m.shouldFail = func(attempt int) bool {
			return attempt <= n
		}
	}
}

// WithFailOn configures the mock to fail on specific attempt numbers
func WithFailOn(attempts ...int) MockStorageOption {
	return func(m *MockStorage) {
		failures := make(map[int]bool, len(attempts))
		for _, n := range attempts {
			failures[n] = true
		}
		m.shouldFail = func(attempt int) bool {
			return failures[attempt]
		}
	}
}

// generateTestCert generates a self-signed certificate in memory for testing
func generateTestCert(t *testing.T) string {
	t.Helper()

	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Return combined PEM (cert + key)
	return string(certPEM) + string(privateKeyPEM)
}

// certMap creates a certificate map for the given cert IDs, all returning the same certData
func certMap(certData string, certIDs ...string) map[string]string {
	m := make(map[string]string, len(certIDs))
	for _, id := range certIDs {
		m["raw-"+id] = certData
	}
	return m
}

// TestCertificateLoadingWithRetry verifies the exponential backoff retry mechanism
// for certificate loading when storage is temporarily unavailable.
func TestCertificateLoadingWithRetry(t *testing.T) {
	certPEM := generateTestCert(t)

	tests := map[string]struct {
		failureCount      int
		expectedAttempts  int
		expectSuccess     bool
		expectCertificate bool
	}{
		"immediate_success": {
			failureCount:      0,
			expectedAttempts:  1,
			expectSuccess:     true,
			expectCertificate: true,
		},
		"retry_once": {
			failureCount:      1,
			expectedAttempts:  2,
			expectSuccess:     true,
			expectCertificate: true,
		},
		"retry_multiple_times": {
			failureCount:      5,
			expectedAttempts:  6,
			expectSuccess:     true,
			expectCertificate: true,
		},
		"retry_many_times": {
			failureCount:      10,
			expectedAttempts:  11,
			expectSuccess:     true,
			expectCertificate: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mockStorage := NewMockStorage(t, certMap(certPEM, "test-cert-id"), WithFailFirst(tt.failureCount))

			handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

			t.Logf("Scenario: MDCB fails %d times before succeeding", tt.failureCount)

			startTime := time.Now()
			certs := handler.List([]string{"test-cert-id"}, CertificatePrivate)
			duration := time.Since(startTime)

			t.Logf("Total time: %.3f seconds", duration.Seconds())
			t.Logf("Total attempts: %d", mockStorage.callCount)

			// Verify attempt count
			if mockStorage.callCount != tt.expectedAttempts {
				t.Errorf("Expected %d attempts, got %d", tt.expectedAttempts, mockStorage.callCount)
			}

			// Verify certificate loaded
			if tt.expectCertificate {
				if len(certs) != 1 {
					t.Errorf("Expected 1 certificate, got %d", len(certs))
				}
				if len(certs) > 0 && certs[0] == nil {
					t.Error("Expected valid certificate, got nil")
				}
			}

			// Verify exponential backoff timing (only for cases with measurable backoff)
			// Backoff config: InitialInterval=100ms, multiplier=2.0, MaxInterval=2s
			// For cases with >= 3 retries, backoff delays are more reliable to measure
			if tt.failureCount >= 3 {
				// Intervals: 100ms, 200ms, 400ms, 800ms, 1600ms, 2000ms (capped), ...
				minExpectedTime := 100 * time.Millisecond // At least the initial interval
				if duration < minExpectedTime {
					t.Errorf("Expected at least %v delay for backoff with %d failures, but completed in %v",
						minExpectedTime, tt.failureCount, duration)
				}
			}
		})
	}
}

// TestCertificateLoadingWithFlakyConnection tests handling of intermittent MDCB failures
func TestCertificateLoadingWithFlakyConnection(t *testing.T) {
	certPEM := generateTestCert(t)

	// Simulate flaky connection: fails on specific calls
	// cert-1: attempts 1 (fail), 2 (fail), 3 (success)
	// cert-2: attempt 4 (fail - flaky!), attempt 5 (success after quick retry)
	// cert-3: attempt 6 (success)
	certIDs := []string{"cert-1", "cert-2", "cert-3"}
	mockStorage := NewMockStorage(t, certMap(certPEM, certIDs...), WithFailOn(1, 2, 4))

	handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

	t.Log("Testing flaky MDCB connection (success → failure → success)")
	certs := handler.List(certIDs, CertificatePrivate)

	t.Logf("Total GetKey calls: %d", mockStorage.callCount)

	// Expected: 3 attempts for cert-1, then 2 for cert-2 (fail + quick retry), then 1 for cert-3
	// Total: 3 + 2 + 1 = 6 calls
	if mockStorage.callCount != 6 {
		t.Errorf("Expected 6 GetKey calls (with flaky connection handling), got %d", mockStorage.callCount)
	}

	// All certificates should still load successfully despite the flaky connection
	if len(certs) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(certs))
	}
	for i, cert := range certs {
		if cert == nil {
			t.Errorf("Certificate %d is nil (flaky connection not handled properly)", i+1)
		}
	}

	t.Log("SUCCESS: Flaky MDCB connection handled gracefully with quick retry")
}

// TestTT14618_MultipleCertificates verifies backoff only happens once for multiple certificates
func TestMultipleCertificatesLoading(t *testing.T) {
	certPEM := generateTestCert(t)

	// Request 5 certificates
	certIDs := []string{"cert-1", "cert-2", "cert-3", "cert-4", "cert-5"}

	// Simulate MDCB failing 3 times before becoming ready
	mockStorage := NewMockStorage(t, certMap(certPEM, certIDs...), WithFailFirst(3))

	handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

	t.Log("Loading 5 certificates with MDCB failing 3 times before ready")
	startTime := time.Now()
	certs := handler.List(certIDs, CertificatePrivate)
	duration := time.Since(startTime)

	t.Logf("Total time: %.3f seconds", duration.Seconds())
	t.Logf("Total GetKey calls: %d", mockStorage.callCount)

	// Without optimization: 5 certs × 4 attempts each = 20 calls
	// With optimization: 4 attempts (first cert) + 4 successful calls (remaining certs) = 8 calls
	expectedCalls := 4 + 4 // 4 retry attempts for first cert, then 4 more for remaining certs
	if mockStorage.callCount != expectedCalls {
		t.Errorf("Expected %d GetKey calls (backoff only for first cert), got %d", expectedCalls, mockStorage.callCount)
	}

	// Verify all certificates loaded successfully
	if len(certs) != 5 {
		t.Errorf("Expected 5 certificates, got %d", len(certs))
	}
	for i, cert := range certs {
		if cert == nil {
			t.Errorf("Certificate %d is nil", i+1)
		}
	}

	// Verify timing is reasonable (not compounded)
	// With compounded backoff: ~4 seconds (5 × ~0.8s)
	// With single backoff: ~0.8 seconds
	maxExpectedTime := 2 * time.Second // Should complete well under 2s
	if duration > maxExpectedTime {
		t.Errorf("Expected completion under %v with single backoff, took %v (possible compounded retry issue)", maxExpectedTime, duration)
	}

	t.Log("SUCCESS: Multiple certificates loaded with single backoff sequence")
}

// TestTT14618_ScaleWith100Certs tests production-scale scenario with 100 certificates
func TestCertificateLoadingScale100(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scale test in short mode")
	}

	certPEM := generateTestCert(t)

	// Generate 100 certificate IDs
	certIDs := make([]string, 100)
	for i := 0; i < 100; i++ {
		certIDs[i] = "cert-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
	}

	// Simulate MDCB down for first 5 attempts (~1 second of retries)
	mockStorage := NewMockStorage(t, certMap(certPEM, certIDs...), WithFailFirst(5))

	handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

	t.Log("SCALE TEST: Loading 100 certificates with MDCB failing 5 times before ready")
	startTime := time.Now()
	certs := handler.List(certIDs, CertificatePrivate)
	duration := time.Since(startTime)

	t.Logf("Total time: %.3f seconds", duration.Seconds())
	t.Logf("Total GetKey calls: %d", mockStorage.callCount)
	t.Logf("Average time per cert: %.1f ms", duration.Seconds()*1000/100)

	// Expected calls: 6 attempts for first cert + 99 successful calls = 105
	expectedCalls := 6 + 99
	if mockStorage.callCount != expectedCalls {
		t.Errorf("Expected %d GetKey calls, got %d", expectedCalls, mockStorage.callCount)
	}

	// Verify all 100 certificates loaded
	if len(certs) != 100 {
		t.Errorf("Expected 100 certificates, got %d", len(certs))
	}
	nilCount := 0
	for _, cert := range certs {
		if cert == nil {
			nilCount++
		}
	}
	if nilCount > 0 {
		t.Errorf("%d out of 100 certificates are nil", nilCount)
	}

	// Performance validation
	// Without optimization: 100 certs × ~1s backoff = ~100 seconds
	// With optimization: single backoff (~1s) + 100 GetKey calls (~instant) = ~1-2 seconds
	maxExpectedTime := 5 * time.Second
	if duration > maxExpectedTime {
		t.Errorf("PERFORMANCE ISSUE: Expected < %v with single backoff for 100 certs, took %v",
			maxExpectedTime, duration)
		t.Errorf("This suggests compounded retries (would be ~100s without optimization)")
	}

	// Calculate theoretical worst case without optimization
	worstCase := 100 * time.Second // If each cert retried independently
	improvement := float64(worstCase) / float64(duration)
	t.Logf("Performance improvement: %.0fx faster than unoptimized approach", improvement)
	t.Log("SUCCESS: 100 certificates loaded efficiently with single backoff!")
}

// TestTT14618_ScaleWith1000Certs tests enterprise-scale scenario with 1000 certificates
func TestCertificateLoadingScale1000(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large scale test in short mode")
	}

	certPEM := generateTestCert(t)

	// Generate 1000 certificate IDs
	certIDs := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		certIDs[i] = fmt.Sprintf("cert-%04d", i)
	}

	// Simulate MDCB down for first 5 attempts (~1 second of retries)
	mockStorage := NewMockStorage(t, certMap(certPEM, certIDs...), WithFailFirst(5))

	handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

	t.Log("LARGE SCALE TEST: Loading 1000 certificates with MDCB failing 5 times before ready")
	startTime := time.Now()
	certs := handler.List(certIDs, CertificatePrivate)
	duration := time.Since(startTime)

	t.Logf("Total time: %.3f seconds", duration.Seconds())
	t.Logf("Total GetKey calls: %d", mockStorage.callCount)
	t.Logf("Average time per cert: %.1f ms", duration.Seconds()*1000/1000)

	// Expected calls: 6 attempts for first cert + 999 successful calls = 1005
	expectedCalls := 6 + 999
	if mockStorage.callCount != expectedCalls {
		t.Errorf("Expected %d GetKey calls, got %d", expectedCalls, mockStorage.callCount)
	}

	// Verify all 1000 certificates loaded
	if len(certs) != 1000 {
		t.Errorf("Expected 1000 certificates, got %d", len(certs))
	}
	nilCount := 0
	for _, cert := range certs {
		if cert == nil {
			nilCount++
		}
	}
	if nilCount > 0 {
		t.Errorf("%d out of 1000 certificates are nil", nilCount)
	}

	// Performance validation
	// Without optimization: 1000 certs × ~1s backoff = ~1000 seconds (~16 minutes!)
	// With optimization: single backoff (~1s) + 1000 GetKey calls (~instant) = ~1-3 seconds
	maxExpectedTime := 5 * time.Second
	if duration > maxExpectedTime {
		t.Errorf("PERFORMANCE ISSUE: Expected < %v with single backoff for 1000 certs, took %v",
			maxExpectedTime, duration)
		t.Errorf("This suggests compounded retries (would be ~1000s without optimization)")
	}

	// Calculate theoretical worst case without optimization
	worstCase := 1000 * time.Second // If each cert retried independently (~16 minutes)
	improvement := float64(worstCase) / float64(duration)
	t.Logf("Performance improvement: %.0fx faster than unoptimized approach", improvement)
	t.Logf("Without optimization: would take ~%.1f minutes", worstCase.Minutes())
	t.Logf("With optimization: took %.3f seconds", duration.Seconds())
	t.Log("SUCCESS: 1000 certificates loaded efficiently with single backoff!")
}

// Benchmark certificate loading with skipBackoff optimization
func BenchmarkCertificateLoadingPerformance(b *testing.B) {
	certPEM := generateTestCert(&testing.T{})

	benchmarks := []struct {
		name      string
		certCount int
		failures  int
	}{
		{"1cert_3failures", 1, 3},
		{"10certs_3failures", 10, 3},
		{"100certs_5failures", 100, 5},
		{"1000certs_5failures", 1000, 5},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Generate certificate IDs
			certIDs := make([]string, bm.certCount)
			for i := 0; i < bm.certCount; i++ {
				certIDs[i] = fmt.Sprintf("cert-%04d", i)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Create fresh mock for each iteration
				mockStorage := NewMockStorage(&testing.T{}, certMap(certPEM, certIDs...), WithFailFirst(bm.failures))

				handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))
				certs := handler.List(certIDs, CertificatePrivate)

				if len(certs) != bm.certCount {
					b.Fatalf("Expected %d certificates, got %d", bm.certCount, len(certs))
				}
			}
		})
	}
}

// Benchmark to compare optimized vs unoptimized behavior
func BenchmarkSkipBackoffOptimization(b *testing.B) {
	certPEM := generateTestCert(&testing.T{})
	certCount := 100
	failures := 3

	// Generate certificate IDs
	certIDs := make([]string, certCount)
	for i := 0; i < certCount; i++ {
		certIDs[i] = fmt.Sprintf("cert-%04d", i)
	}

	b.Run("optimized_with_skipBackoff", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mockStorage := NewMockStorage(&testing.T{}, certMap(certPEM, certIDs...), WithFailFirst(failures))

			handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))
			certs := handler.List(certIDs, CertificatePrivate)

			if len(certs) != certCount {
				b.Fatalf("Expected %d certificates, got %d", certCount, len(certs))
			}
		}
	})

	b.Run("unoptimized_without_skipBackoff", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mockStorage := NewMockStorage(&testing.T{}, certMap(certPEM, certIDs...), WithFailFirst(failures))

			handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))

			// Simulate unoptimized behavior: each cert does full backoff
			// Load certificates one at a time (no skipBackoff benefit)
			loadedCount := 0
			for _, id := range certIDs {
				singleCert := handler.List([]string{id}, CertificatePrivate)
				if len(singleCert) > 0 {
					loadedCount++
				}
			}

			if loadedCount != certCount {
				b.Fatalf("Expected %d certificates, got %d", certCount, loadedCount)
			}
		}
	})
}

// Benchmark cache hit performance (no MDCB calls)
func BenchmarkCertificateCacheHit(b *testing.B) {
	certPEM := generateTestCert(&testing.T{})

	// Pre-load certificates into cache
	certIDs := []string{"cert-1", "cert-2", "cert-3", "cert-4", "cert-5"}
	mockStorage := NewMockStorage(&testing.T{}, certMap(certPEM, certIDs...), WithFailFirst(0))

	handler := NewCertificateManager(mockStorage, "secret", nil, false, WithMaxRetries(0))
	handler.List(certIDs, CertificatePrivate)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		certs := handler.List(certIDs, CertificatePrivate)
		if len(certs) != len(certIDs) {
			b.Fatalf("Expected %d certificates, got %d", len(certIDs), len(certs))
		}
	}
}

// TestMaxRetriesLimit verifies that the maxRetries configuration limits retry attempts correctly
func TestMaxRetriesLimit(t *testing.T) {
	certPEM := generateTestCert(t)

	testCases := []struct {
		name          string
		maxRetries    int
		failureCount  int // How many times to fail before succeeding
		expectedCalls int // Expected total GetKey calls
		shouldSucceed bool
	}{
		{
			name:          "maxRetries=3 with 2 failures - should succeed on 3rd attempt",
			maxRetries:    3,
			failureCount:  2,
			expectedCalls: 3, // Initial + 2 retries = 3 total
			shouldSucceed: true,
		},
		{
			name:          "maxRetries=3 with 3 failures - should succeed on 4th attempt",
			maxRetries:    3,
			failureCount:  3,
			expectedCalls: 4, // Initial + 3 retries = 4 total
			shouldSucceed: true,
		},
		{
			name:          "maxRetries=3 with 4 failures - should fail (exceeds limit)",
			maxRetries:    3,
			failureCount:  4,
			expectedCalls: 4, // Initial + 3 retries = 4 total, then stops
			shouldSucceed: false,
		},
		{
			name:          "maxRetries=1 with 1 failure - should succeed on 2nd attempt",
			maxRetries:    1,
			failureCount:  1,
			expectedCalls: 2, // Initial + 1 retry = 2 total
			shouldSucceed: true,
		},
		{
			name:          "maxRetries=1 with 2 failures - should fail (exceeds limit)",
			maxRetries:    1,
			failureCount:  2,
			expectedCalls: 2, // Initial + 1 retry = 2 total, then stops
			shouldSucceed: false,
		},
		{
			name:          "maxRetries=0 (unlimited) with many failures - should eventually succeed",
			maxRetries:    0,
			failureCount:  10,
			expectedCalls: 11, // All attempts until success
			shouldSucceed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockStorage := NewMockStorage(t, certMap(certPEM, "test-cert-id"), WithFailFirst(tc.failureCount))

			// Set short intervals for faster test execution
			handler := NewCertificateManager(
				mockStorage,
				"secret",
				nil,
				false,
				WithMaxRetries(tc.maxRetries),
				WithBackoffIntervals(
					time.Second*2,        // maxElapsedTime - short but enough for retries
					time.Millisecond*50,  // initialInterval
					time.Millisecond*100, // maxInterval
				),
			)

			certIDs := []string{"test-cert-id"}
			certs := handler.List(certIDs, CertificatePrivate)

			t.Logf("Total GetKey calls: %d (expected: %d)", mockStorage.callCount, tc.expectedCalls)

			// Verify call count
			if mockStorage.callCount != tc.expectedCalls {
				t.Errorf("Expected %d GetKey calls, got %d", tc.expectedCalls, mockStorage.callCount)
			}

			// Verify success/failure
			if tc.shouldSucceed {
				if len(certs) != 1 || certs[0] == nil {
					t.Errorf("Expected certificate to be loaded successfully")
				}
			} else {
				if len(certs) == 1 && certs[0] != nil {
					t.Errorf("Expected certificate loading to fail (exceed maxRetries)")
				}
			}
		})
	}
}

// TestRetryEnabledFlag verifies that retry can be disabled via the retryEnabled flag
func TestRetryEnabledFlag(t *testing.T) {
	certPEM := generateTestCert(t)

	testCases := []struct {
		name          string
		retryEnabled  bool
		failureCount  int
		expectedCalls int
		shouldSucceed bool
	}{
		{
			name:          "retry enabled - should retry and succeed",
			retryEnabled:  true,
			failureCount:  3,
			expectedCalls: 4, // Initial + 3 retries
			shouldSucceed: true,
		},
		{
			name:          "retry disabled - should fail immediately on first error",
			retryEnabled:  false,
			failureCount:  1,
			expectedCalls: 1, // Only initial attempt, no retries
			shouldSucceed: false,
		},
		{
			name:          "retry disabled with immediate success - should succeed",
			retryEnabled:  false,
			failureCount:  0,
			expectedCalls: 1, // Only initial attempt
			shouldSucceed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockStorage := NewMockStorage(t, certMap(certPEM, "test-cert-id"), WithFailFirst(tc.failureCount))

			handler := NewCertificateManager(
				mockStorage,
				"secret",
				nil,
				false,
				WithRetryEnabled(tc.retryEnabled),
				WithMaxRetries(3),
				WithBackoffIntervals(
					time.Second*2,        // maxElapsedTime
					time.Millisecond*50,  // initialInterval
					time.Millisecond*100, // maxInterval
				),
			)

			certIDs := []string{"test-cert-id"}
			certs := handler.List(certIDs, CertificatePrivate)

			t.Logf("Total GetKey calls: %d (expected: %d)", mockStorage.callCount, tc.expectedCalls)

			// Verify call count
			if mockStorage.callCount != tc.expectedCalls {
				t.Errorf("Expected %d GetKey calls, got %d", tc.expectedCalls, mockStorage.callCount)
			}

			// Verify success/failure
			if tc.shouldSucceed {
				if len(certs) != 1 || certs[0] == nil {
					t.Errorf("Expected certificate to be loaded successfully")
				}
			} else {
				if len(certs) == 1 && certs[0] != nil {
					t.Errorf("Expected certificate loading to fail (retry disabled)")
				}
			}
		})
	}
}

// TestConfigDefaults verifies that default values are used correctly
func TestConfigDefaults(t *testing.T) {
	certPEM := generateTestCert(t)

	// Test with defaults (should behave like maxRetries=3)
	mockStorage := NewMockStorage(t, certMap(certPEM, "test-cert-id"), WithFailFirst(2))

	// Use the default values from constants
	handler := NewCertificateManager(
		mockStorage,
		"secret",
		nil,
		false,
		WithRetryEnabled(DefaultRPCCertFetchRetryEnabled), // Should be true
		WithMaxRetries(DefaultRPCCertFetchMaxRetries),     // Should be 5
		WithBackoffIntervals(
			time.Second*10,       // maxElapsedTime
			time.Millisecond*100, // initialInterval
			time.Millisecond*500, // maxInterval
		),
	)

	certIDs := []string{"test-cert-id"}
	certs := handler.List(certIDs, CertificatePrivate)

	// Should succeed after 3 attempts (2 failures + 1 success)
	if len(certs) != 1 || certs[0] == nil {
		t.Errorf("Expected certificate to be loaded successfully with defaults")
	}

	expectedCalls := 3
	if mockStorage.callCount != expectedCalls {
		t.Errorf("Expected %d GetKey calls with defaults, got %d", expectedCalls, mockStorage.callCount)
	}

	t.Logf("SUCCESS: Default config values work correctly (retryEnabled=%v, maxRetries=%d)",
		DefaultRPCCertFetchRetryEnabled, DefaultRPCCertFetchMaxRetries)
}
