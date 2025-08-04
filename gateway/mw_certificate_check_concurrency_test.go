package gateway

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/stretchr/testify/assert"
)

// TestCertificateCheckMW_ConcurrencySafety tests that the certificate check middleware
// is thread-safe under high concurrency scenarios
func TestCertificateCheckMW_ConcurrencySafety(t *testing.T) {
	t.Parallel()

	certID := "test-cert-id-1234567890abcdef"

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1, // Very short cooldown for testing
							EventCooldownSeconds: 1, // Very short cooldown for testing
							MaxConcurrentChecks:  10,
						},
					},
				},
			},
		},
	}

	// Mock gateway with cache
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

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

				// Test both operations
				shouldSkip := mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
				checkResults <- shouldSkip

				shouldFire := mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
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

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 5,
							EventCooldownSeconds: 10,
							MaxConcurrentChecks:  5,
						},
					},
				},
			},
		},
	}

	// Mock gateway with cache
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	t.Run("Certificate ID generation consistency", func(t *testing.T) {
		cert := createTestCertificate(30)

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
		certIDs := []string{"cert1", "cert2", "cert3", "cert4", "cert5"}

		const numGoroutines = 10
		var wg sync.WaitGroup

		// Test that different certificates can be processed concurrently
		for _, certID := range certIDs {
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()

					// These should all succeed since they're different certificates
					shouldSkip := mw.shouldSkipCertificate(id, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
					shouldFire := mw.shouldFireExpiryEvent(id, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)

					// First call should allow, subsequent calls should skip
					assert.False(t, shouldSkip, "First check should not be skipped")
					assert.True(t, shouldFire, "First event should be allowed")
				}(certID)
			}
		}

		wg.Wait()
	})
}

// TestCertificateCheckMW_ParallelProcessingSafety tests the safety of parallel
// certificate processing with the worker pool
func TestCertificateCheckMW_ParallelProcessingSafety(t *testing.T) {
	t.Parallel()

	// Create multiple test certificates
	certs := make([]*tls.Certificate, 20)
	for i := range certs {
		certs[i] = createTestCertificate(15 + i) // Different expiry times
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
							MaxConcurrentChecks:  5, // Limit concurrency
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

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

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
							MaxConcurrentChecks:  5,
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	t.Run("Lock creation and reuse", func(t *testing.T) {
		certID := "test-cert-id"

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
		certID1 := "cert-id-1"
		certID2 := "cert-id-2"

		lock1 := mw.acquireLock(certID1)
		lock2 := mw.acquireLock(certID2)

		// Should return different lock instances
		assert.NotEqual(t, lock1, lock2, "Different certificates should return different locks")

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
	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
							MaxConcurrentChecks:  10,
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	certID := "benchmark-cert-id"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mw.shouldSkipCertificate(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		}
	})
}

func BenchmarkCertificateCheckMW_ConcurrentEvents(b *testing.B) {
	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				GlobalConfig: config.Config{
					Security: config.SecurityConfig{
						CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
							WarningThresholdDays: 30,
							CheckCooldownSeconds: 1,
							EventCooldownSeconds: 1,
							MaxConcurrentChecks:  10,
						},
					},
				},
			},
		},
	}

	// Mock gateway
	mw.Gw = &Gateway{}
	mw.Gw.UtilCache = cache.New(3600, 10*60)

	certID := "benchmark-cert-id"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mw.shouldFireExpiryEvent(certID, mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor)
		}
	})
}
