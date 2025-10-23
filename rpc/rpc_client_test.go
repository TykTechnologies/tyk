package rpc

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

func TestRecoveryFromEmergencyMode(t *testing.T) {
	if IsEmergencyMode() {
		t.Fatal("expected not to be in emergency mode before initiating login attempt")
	}
	hasAPIKey := func() bool { return true }
	// group login has the same recovery api so we don't need to test for it.
	isGroup := func() bool { return false }

	ok := doLoginWithRetries(func() error {
		return errLogFailed
	}, func() error {
		return errLogFailed
	}, hasAPIKey, isGroup)
	if ok {
		t.Fatal("expected to fail login")
	}
	if !IsEmergencyMode() {
		t.Fatal("expected to be in emergency mode")
	}
	// Lets succeed after second retry
	x := 0
	ok = doLoginWithRetries(func() error {
		if x == 0 {
			x++
			return errLogFailed
		}
		return nil
	}, func() error {
		return errLogFailed
	}, hasAPIKey, isGroup)
	if !ok {
		t.Fatal("expected login to succeed")
	}
	if IsEmergencyMode() {
		t.Fatal("expected to recover from emergency mode")
	}
}

func TestClientIsConnected(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		connected bool
		expected  bool
	}{
		{
			name:      "When client is connected and not in emergency mode",
			connected: true,
			expected:  true,
		},
		{
			name:      "When client is disconnected and not in emergency mode",
			connected: false,
			expected:  false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			r := rpcOpts{}
			r.clientIsConnected.Store(tt.connected)
			defer func() {
				r.clientIsConnected.Store(false)
			}()

			got := r.ClientIsConnected()
			if got != tt.expected {
				t.Errorf("ClientIsConnected() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestHandleRPCError_DNSUnchanged_NoRetry verifies that handleRPCError returns false
// when DNS hasn't changed, which should prevent retries when wrapped with backoff.Permanent
func TestHandleRPCError_DNSUnchanged_NoRetry(t *testing.T) {
	// Save original values
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalDNSChecked := values.GetDNSCheckedAfterError()
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		values.SetDNSCheckedAfterError(originalDNSChecked)
		values.SetEmergencyMode(originalEmergencyMode)
	}()

	// Setup: simulate initial DNS resolution
	lastResolvedIPs = []string{"192.168.1.1"}
	values.SetDNSCheckedAfterError(false)
	values.SetEmergencyMode(false)

	// Mock DNS resolver that returns same IPs (DNS unchanged)
	mockResolver := &MockDNSResolver{
		LookupIPFunc: func(_ string) ([]net.IP, error) {
			return makeIPs("192.168.1.1"), nil
		},
	}
	dnsResolver = mockResolver

	reconnectCalled := false
	safeReconnectRPCClient = func(_ bool) {
		reconnectCalled = true
	}

	// Test 1: Generic RPC timeout error (not DNS-related)
	err := errors.New("Cannot obtain response during timeout")
	shouldRetry := handleRPCError(err, "example.com:8080")

	if shouldRetry {
		t.Error("handleRPCError should return false for non-DNS errors")
	}
	if reconnectCalled {
		t.Error("Should not attempt reconnect for non-DNS errors")
	}

	// Reset for next test
	values.SetDNSCheckedAfterError(false)
	reconnectCalled = false

	// Test 2: DNS error but DNS unchanged
	err = errors.New("dial tcp: lookup mdcb.example.com: no such host")
	shouldRetry = handleRPCError(err, "example.com:8080")

	if shouldRetry {
		t.Error("handleRPCError should return false when DNS hasn't changed")
	}
	if reconnectCalled {
		t.Error("Should not reconnect when DNS hasn't changed")
	}
}

// TestHandleRPCError_DNSChanged_Retry verifies that handleRPCError returns true
// when DNS has actually changed, allowing retries
func TestHandleRPCError_DNSChanged_Retry(t *testing.T) {
	// Save original values
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalDNSChecked := values.GetDNSCheckedAfterError()
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		values.SetDNSCheckedAfterError(originalDNSChecked)
		values.SetEmergencyMode(originalEmergencyMode)
	}()

	// Setup: simulate initial DNS resolution
	lastResolvedIPs = []string{"192.168.1.1"}
	values.SetDNSCheckedAfterError(false)
	values.SetEmergencyMode(false)

	// Mock DNS resolver that returns different IPs (DNS changed)
	mockResolver := &MockDNSResolver{
		LookupIPFunc: func(_ string) ([]net.IP, error) {
			return makeIPs("192.168.1.2"), nil
		},
	}
	dnsResolver = mockResolver

	reconnectCalled := false
	safeReconnectRPCClient = func(_ bool) {
		reconnectCalled = true
	}

	// Test: DNS error with DNS changed
	err := errors.New("dial tcp: lookup mdcb.example.com: no such host")
	shouldRetry := handleRPCError(err, "example.com:8080")

	if !shouldRetry {
		t.Error("handleRPCError should return true when DNS has changed")
	}
	if !reconnectCalled {
		t.Error("Should attempt reconnect when DNS has changed")
	}
}

// TestBackoffPermanent_StopsRetries verifies that backoff.Permanent prevents retries
// This tests the core mechanism used in FuncClientSingleton when DNS hasn't changed
func TestBackoffPermanent_StopsRetries(t *testing.T) {
	callCount := 0
	testError := errors.New("test error")

	// Test backoff with Permanent error - should stop immediately
	start := time.Now()
	err := backoff.Retry(func() error {
		callCount++
		return backoff.Permanent(testError)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 3))
	elapsed := time.Since(start)

	// Should have called only once
	if callCount != 1 {
		t.Errorf("Expected 1 call with backoff.Permanent, got %d", callCount)
	}

	// Should return the original error
	if err == nil || err.Error() != testError.Error() {
		t.Errorf("Expected original error, got %v", err)
	}

	// Should fail fast (no retries)
	if elapsed > 50*time.Millisecond {
		t.Errorf("Expected immediate failure with Permanent, took %v", elapsed)
	}

	t.Logf("backoff.Permanent stopped retries after %d calls in %v", callCount, elapsed)
}

// TestBackoffRetry_Retries verifies that normal errors cause retries
// This tests the core mechanism used in FuncClientSingleton when DNS changes
func TestBackoffRetry_Retries(t *testing.T) {
	callCount := 0
	testError := errors.New("test error")

	// Test backoff with normal error - should retry up to max
	start := time.Now()
	err := backoff.Retry(func() error {
		callCount++
		if callCount < 3 {
			return testError // Keep failing
		}
		return nil // Success on 3rd attempt
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 5))
	elapsed := time.Since(start)

	// Should have called 3 times (failed twice, succeeded on 3rd)
	if callCount != 3 {
		t.Errorf("Expected 3 calls (2 retries + success), got %d", callCount)
	}

	// Should succeed
	if err != nil {
		t.Errorf("Expected success after retries, got error: %v", err)
	}

	// Should have taken some time (at least 2 backoff intervals)
	if elapsed < 15*time.Millisecond {
		t.Errorf("Expected some delay for retries, took only %v", elapsed)
	}

	t.Logf("Normal error retried %d times in %v until success", callCount-1, elapsed)
}

// TestBackoffRetry_MaxRetries verifies that retries stop after max attempts
func TestBackoffRetry_MaxRetries(t *testing.T) {
	callCount := 0
	testError := errors.New("persistent error")

	// Test backoff that keeps failing - should stop at max retries
	start := time.Now()
	err := backoff.Retry(func() error {
		callCount++
		return testError // Always fail
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(5*time.Millisecond), 3))
	elapsed := time.Since(start)

	// Should have called 4 times (initial + 3 retries)
	if callCount != 4 {
		t.Errorf("Expected 4 calls (initial + 3 retries), got %d", callCount)
	}

	// Should return error after exhausting retries
	if err == nil {
		t.Error("Expected error after exhausting retries")
	}

	t.Logf("Exhausted max retries after %d calls in %v", callCount, elapsed)
}

// TestRPCErrorRetryBehavior_Integration verifies the complete retry logic flow
// This integration test validates that handleRPCError correctly controls retry behavior
func TestRPCErrorRetryBehavior_Integration(t *testing.T) {
	// Save original values
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalDNSChecked := values.GetDNSCheckedAfterError()
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		values.SetDNSCheckedAfterError(originalDNSChecked)
		values.SetEmergencyMode(originalEmergencyMode)
	}()

	t.Run("Scenario 1: Non-DNS error - no retries", func(t *testing.T) {
		values.SetDNSCheckedAfterError(false)
		values.SetEmergencyMode(false)
		lastResolvedIPs = []string{"192.168.1.1"}

		reconnectCalled := false
		safeReconnectRPCClient = func(_ bool) {
			reconnectCalled = true
		}

		callCount := 0
		nonDNSError := errors.New("Cannot obtain response during timeout")

		// Simulate the backoff retry logic from FuncClientSingleton
		err := backoff.Retry(func() error {
			callCount++
			rpcErr := nonDNSError

			// Simulate error handling
			if rpcErr != nil {
				if handleRPCError(rpcErr, "example.com:8080") {
					return rpcErr // Retry
				}
				return backoff.Permanent(rpcErr) // No retry
			}
			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 3))

		if callCount != 1 {
			t.Errorf("Scenario 1: Expected 1 call (no retries), got %d", callCount)
		}
		if reconnectCalled {
			t.Error("Scenario 1: Should not reconnect for non-DNS error")
		}
		if err == nil {
			t.Error("Scenario 1: Expected error to be returned")
		}
		t.Logf("Scenario 1: Failed fast with %d call(s), no reconnect", callCount)
	})

	t.Run("Scenario 2: DNS error, DNS unchanged - no retries", func(t *testing.T) {
		values.SetDNSCheckedAfterError(false)
		values.SetEmergencyMode(false)
		lastResolvedIPs = []string{"192.168.1.1"}

		// DNS returns same IPs
		mockResolver := &MockDNSResolver{
			LookupIPFunc: func(_ string) ([]net.IP, error) {
				return makeIPs("192.168.1.1"), nil
			},
		}
		dnsResolver = mockResolver

		reconnectCalled := false
		safeReconnectRPCClient = func(_ bool) {
			reconnectCalled = true
		}

		callCount := 0
		dnsError := errors.New("dial tcp: lookup mdcb.example.com: no such host")

		err := backoff.Retry(func() error {
			callCount++
			rpcErr := dnsError

			if rpcErr != nil {
				if handleRPCError(rpcErr, "example.com:8080") {
					return rpcErr // Retry
				}
				return backoff.Permanent(rpcErr) // No retry
			}
			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 3))

		if callCount != 1 {
			t.Errorf("Scenario 2: Expected 1 call (no retries), got %d", callCount)
		}
		if reconnectCalled {
			t.Error("Scenario 2: Should not reconnect when DNS unchanged")
		}
		if err == nil {
			t.Error("Scenario 2: Expected error to be returned")
		}
		t.Logf("Scenario 2: DNS unchanged, failed fast with %d call(s)", callCount)
	})

	t.Run("Scenario 3: DNS error, DNS changed - retries until success", func(t *testing.T) {
		values.SetDNSCheckedAfterError(false)
		values.SetEmergencyMode(false)
		lastResolvedIPs = []string{"192.168.1.1"}

		// DNS returns different IPs
		mockResolver := &MockDNSResolver{
			LookupIPFunc: func(_ string) ([]net.IP, error) {
				return makeIPs("192.168.1.2"), nil
			},
		}
		dnsResolver = mockResolver

		reconnectCount := 0
		safeReconnectRPCClient = func(_ bool) {
			reconnectCount++
			values.SetDNSCheckedAfterError(false) // Reset after reconnect
		}

		callCount := 0
		dnsError := errors.New("dial tcp: lookup mdcb.example.com: no such host")

		err := backoff.Retry(func() error {
			callCount++

			// First call fails with DNS error, subsequent calls succeed
			if callCount == 1 {
				rpcErr := dnsError
				if handleRPCError(rpcErr, "example.com:8080") {
					return rpcErr // Triggers retry
				}
				return backoff.Permanent(rpcErr)
			}

			// After reconnect, succeed
			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 3))

		if callCount < 2 {
			t.Errorf("Scenario 3: Expected at least 2 calls (retry), got %d", callCount)
		}
		if reconnectCount != 1 {
			t.Errorf("Scenario 3: Expected 1 reconnect, got %d", reconnectCount)
		}
		if err != nil {
			t.Errorf("Scenario 3: Expected success after retry, got error: %v", err)
		}
		t.Logf("Scenario 3: DNS changed, succeeded after %d call(s) and %d reconnect(s)", callCount, reconnectCount)
	})
}
