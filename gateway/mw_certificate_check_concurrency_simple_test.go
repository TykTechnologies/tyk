package gateway

import (
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/stretchr/testify/assert"
)

// TestCertificateCheckMW_SimpleConcurrency tests basic concurrency safety
func TestCertificateCheckMW_SimpleConcurrency(t *testing.T) {
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
		lock1.Unlock()
		lock2.Lock()
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
		lock1.Unlock()
		lock2.Unlock()

		// No deadlock should occur
		assert.True(t, true, "Independent lock operations should complete successfully")
	})

	t.Run("Concurrent certificate checks", func(t *testing.T) {
		certID := "concurrent-test-cert"
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
		certID := "concurrent-event-test-cert"
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
