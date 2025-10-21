package rpc

import (
	"errors"
	"net"
	"testing"
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
		LookupIPFunc: func(host string) ([]net.IP, error) {
			return makeIPs("192.168.1.1"), nil
		},
	}
	dnsResolver = mockResolver

	reconnectCalled := false
	safeReconnectRPCClient = func(suppressRegister bool) {
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
		LookupIPFunc: func(host string) ([]net.IP, error) {
			return makeIPs("192.168.1.2"), nil
		},
	}
	dnsResolver = mockResolver

	reconnectCalled := false
	safeReconnectRPCClient = func(suppressRegister bool) {
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
