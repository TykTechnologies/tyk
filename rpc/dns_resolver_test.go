package rpc

import (
	"context"
	"errors"
	"net"
	"testing"
)

// Helper function to create IP addresses for testing
func makeIPs(ips ...string) []net.IP {
	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = net.ParseIP(ip)
	}
	return result
}

// MockDNSResolver implements DNSResolver for testing
type MockDNSResolver struct {
	LookupIPFunc func(host string) ([]net.IP, error)
}

func (m *MockDNSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return m.LookupIPFunc(host)
}

func TestCheckDNSAndReconnect(t *testing.T) {
	// Save original values and restore after test
	originalSafeReconnect := safeReconnectRPCClient
	originalIPs := lastResolvedIPs
	originalResolver := dnsResolver

	defer func() {
		safeReconnectRPCClient = originalSafeReconnect
		lastResolvedIPs = originalIPs
		dnsResolver = originalResolver
	}()

	// Test cases
	tests := []struct {
		name                string
		connectionString    string
		initialIPs          []string
		resolvedIPs         []net.IP
		resolveError        error
		expectedResult      bool
		expectReconnectCall bool
		expectDNSLookup     bool
	}{
		{
			name:                "DNS changed - should reconnect",
			connectionString:    "example.com:8080",
			initialIPs:          []string{"192.168.1.1"},
			resolvedIPs:         makeIPs("192.168.1.2"),
			resolveError:        nil,
			expectedResult:      true,
			expectReconnectCall: true,
			expectDNSLookup:     true,
		},
		{
			name:                "DNS unchanged - should not reconnect",
			connectionString:    "example.com:8080",
			initialIPs:          []string{"192.168.1.1"},
			resolvedIPs:         makeIPs("192.168.1.1"),
			resolveError:        nil,
			expectedResult:      false,
			expectReconnectCall: false,
			expectDNSLookup:     true,
		},
		{
			name:                "DNS resolution error - should not reconnect",
			connectionString:    "example.com:8080",
			initialIPs:          []string{"192.168.1.1"},
			resolvedIPs:         nil,
			resolveError:        errors.New("DNS resolution failed"),
			expectedResult:      false,
			expectReconnectCall: false,
			expectDNSLookup:     true,
		},
		{
			name:                "Invalid connection string - should not check DNS or reconnect",
			connectionString:    "invalid-no-port", // Missing port
			initialIPs:          []string{"192.168.1.1"},
			resolvedIPs:         makeIPs("192.168.1.2"),
			resolveError:        nil,
			expectedResult:      false,
			expectReconnectCall: false,
			expectDNSLookup:     false,
		},
		{
			name:                "Empty connection string - should not check DNS or reconnect",
			connectionString:    "",
			initialIPs:          []string{"192.168.1.1"},
			resolvedIPs:         makeIPs("192.168.1.2"),
			resolveError:        nil,
			expectedResult:      false,
			expectReconnectCall: false,
			expectDNSLookup:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set initial IPs
			lastResolvedIPs = tt.initialIPs

			// Create a mock resolver
			dnsLookupCalled := false
			mockResolver := &MockDNSResolver{}
			mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
				_ = host // unused
				dnsLookupCalled = true
				return tt.resolvedIPs, tt.resolveError
			}
			dnsResolver = mockResolver

			// Create a mock reconnect function
			reconnectCalled := false
			safeReconnectRPCClient = func(suppressRegister bool) {
				_ = suppressRegister // unused
				reconnectCalled = true
			}

			// Call the function
			result := checkDNSAndReconnect(tt.connectionString, false)

			// Check result
			if result != tt.expectedResult {
				t.Errorf("checkDNSAndReconnect() = %v, expected %v", result, tt.expectedResult)
			}

			// Check if reconnect was called as expected
			if reconnectCalled != tt.expectReconnectCall {
				t.Errorf("reconnect called = %v, expected %v", reconnectCalled, tt.expectReconnectCall)
			}

			// Check if DNS lookup was performed as expected
			if dnsLookupCalled != tt.expectDNSLookup {
				t.Errorf("DNS lookup performed = %v, expected %v", dnsLookupCalled, tt.expectDNSLookup)
			}
		})
	}
}

func TestUpdateResolvedIPs(t *testing.T) {
	// Save original values and restore after test
	originalIPs := lastResolvedIPs
	defer func() {
		lastResolvedIPs = originalIPs
	}()

	// Create a mock resolver
	mockResolver := &MockDNSResolver{}

	// Test cases
	tests := []struct {
		name           string
		initialIPs     []string
		resolvedIPs    []net.IP
		resolveError   error
		expectedResult bool
		expectedIPs    []string
	}{
		{
			name:           "first resolution",
			initialIPs:     nil,
			resolvedIPs:    makeIPs("192.168.1.1", "192.168.1.2"),
			resolveError:   nil,
			expectedResult: true,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name:           "same IPs",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2"},
			resolvedIPs:    makeIPs("192.168.1.1", "192.168.1.2"),
			resolveError:   nil,
			expectedResult: false,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name:           "different IPs",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2"},
			resolvedIPs:    makeIPs("192.168.1.1", "192.168.1.3"),
			resolveError:   nil,
			expectedResult: true,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.3"},
		},
		{
			name:           "different order",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2"},
			resolvedIPs:    makeIPs("192.168.1.2", "192.168.1.1"),
			resolveError:   nil,
			expectedResult: false,                                  // Order doesn't matter
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2"}, // Original IPs should remain
		},
		{
			name:           "more IPs",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2"},
			resolvedIPs:    makeIPs("192.168.1.1", "192.168.1.2", "192.168.1.3"),
			resolveError:   nil,
			expectedResult: true,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:           "fewer IPs",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			resolvedIPs:    makeIPs("192.168.1.1", "192.168.1.2"),
			resolveError:   nil,
			expectedResult: true,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name:           "resolve error",
			initialIPs:     []string{"192.168.1.1", "192.168.1.2"},
			resolvedIPs:    nil,
			resolveError:   errors.New("DNS resolution failed"),
			expectedResult: false,
			expectedIPs:    []string{"192.168.1.1", "192.168.1.2"}, // Original IPs should remain
		},
		{
			name:           "mixed IPv4 and IPv6",
			initialIPs:     []string{"192.168.1.1"},
			resolvedIPs:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("2001:db8::1")},
			resolveError:   nil,
			expectedResult: false, // Only IPv4 addresses are considered, so no change
			expectedIPs:    []string{"192.168.1.1"},
		},
		{
			name:           "only IPv6",
			initialIPs:     []string{"192.168.1.1"},
			resolvedIPs:    []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")},
			resolveError:   nil,
			expectedResult: true,       // All IPv4 addresses are gone
			expectedIPs:    []string{}, // Should be empty since no IPv4 addresses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set initial IPs
			lastResolvedIPs = tt.initialIPs

			// Configure mock resolver
			mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
				_ = host // unused
				return tt.resolvedIPs, tt.resolveError
			}

			// Call the function
			result := updateResolvedIPs(context.Background(), "example.com", mockResolver)

			// Check result
			if result != tt.expectedResult {
				t.Errorf("updateResolvedIPs() = %v, expected %v", result, tt.expectedResult)
			}

			// Check that lastResolvedIPs was updated correctly
			if !equalStringSlices(lastResolvedIPs, tt.expectedIPs) {
				t.Errorf("lastResolvedIPs = %v, expected %v", lastResolvedIPs, tt.expectedIPs)
			}
		})
	}
}

func TestCheckAndHandleDNSChange(t *testing.T) {
	// Save original values and restore after test
	originalSafeReconnectRPCClient := safeReconnectRPCClient
	originalIPs := lastResolvedIPs
	originalResolver := dnsResolver

	// Save original values state
	originalDNSChecked := values.GetDNSCheckedAfterError()
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		// Restore all original values
		safeReconnectRPCClient = originalSafeReconnectRPCClient
		lastResolvedIPs = originalIPs
		dnsResolver = originalResolver
		values.SetDNSCheckedAfterError(originalDNSChecked)
		values.SetEmergencyMode(originalEmergencyMode)
	}()

	// Test cases
	tests := []struct {
		name                 string
		initialIPs           []string
		resolvedIPs          []net.IP
		resolveError         error
		dnsCheckedAfterError bool
		emergencyMode        bool
		expectedDNSChanged   bool
		expectedShouldRetry  bool
		expectReconnectCall  bool
	}{
		{
			name:                 "DNS changed - should reconnect and retry",
			initialIPs:           []string{"192.168.1.1"},
			resolvedIPs:          makeIPs("192.168.1.2"),
			resolveError:         nil,
			dnsCheckedAfterError: false,
			emergencyMode:        false,
			expectedDNSChanged:   true,
			expectedShouldRetry:  true,
			expectReconnectCall:  true,
		},
		{
			name:                 "DNS unchanged - should not reconnect or retry",
			initialIPs:           []string{"192.168.1.1"},
			resolvedIPs:          makeIPs("192.168.1.1"),
			resolveError:         nil,
			dnsCheckedAfterError: false,
			emergencyMode:        false,
			expectedDNSChanged:   false,
			expectedShouldRetry:  false,
			expectReconnectCall:  false,
		},
		{
			name:                 "DNS already checked - should skip check",
			initialIPs:           []string{"192.168.1.1"},
			resolvedIPs:          makeIPs("192.168.1.2"), // Would trigger reconnect if checked
			resolveError:         nil,
			dnsCheckedAfterError: true,
			emergencyMode:        false,
			expectedDNSChanged:   false,
			expectedShouldRetry:  false,
			expectReconnectCall:  false,
		},
		{
			name:                 "In emergency mode - should skip check",
			initialIPs:           []string{"192.168.1.1"},
			resolvedIPs:          makeIPs("192.168.1.2"), // Would trigger reconnect if checked
			resolveError:         nil,
			dnsCheckedAfterError: false,
			emergencyMode:        true,
			expectedDNSChanged:   false,
			expectedShouldRetry:  false,
			expectReconnectCall:  false,
		},
		{
			name:                 "DNS resolution error - should not reconnect",
			initialIPs:           []string{"192.168.1.1"},
			resolvedIPs:          nil,
			resolveError:         errors.New("DNS resolution failed"),
			dnsCheckedAfterError: false,
			emergencyMode:        false,
			expectedDNSChanged:   false,
			expectedShouldRetry:  false,
			expectReconnectCall:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set initial IPs
			lastResolvedIPs = tt.initialIPs

			// Create a mock resolver
			mockResolver := &MockDNSResolver{}
			mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
				_ = host // unused
				return tt.resolvedIPs, tt.resolveError
			}
			dnsResolver = mockResolver

			// Set initial state values
			values.SetDNSCheckedAfterError(tt.dnsCheckedAfterError)
			values.SetEmergencyMode(tt.emergencyMode)

			// Create a mock reconnect function
			reconnectCalled := false
			safeReconnectRPCClient = func(suppressRegister bool) {
				_ = suppressRegister // unused
				reconnectCalled = true
			}

			// Call the function
			dnsChanged, shouldRetry := checkAndHandleDNSChange("example.com:8080", false)

			// Check results
			if dnsChanged != tt.expectedDNSChanged {
				t.Errorf("dnsChanged = %v, expected %v", dnsChanged, tt.expectedDNSChanged)
			}

			if shouldRetry != tt.expectedShouldRetry {
				t.Errorf("shouldRetry = %v, expected %v", shouldRetry, tt.expectedShouldRetry)
			}

			// Check if reconnect was called as expected
			if reconnectCalled != tt.expectReconnectCall {
				t.Errorf("reconnect called = %v, expected %v", reconnectCalled, tt.expectReconnectCall)
			}

			// If we weren't already in DNS checked state and not in emergency mode,
			// verify that DNS checked flag was set to true
			if !tt.dnsCheckedAfterError && !tt.emergencyMode {
				if !values.GetDNSCheckedAfterError() {
					t.Error("DNS checked flag should have been set to true")
				}
			}
		})
	}
}

func TestDNSIsOnlyCheckedOncePerConnectionIssue(t *testing.T) {
	// Save original values and restore after test
	originalSafeReconnectRPCClient := safeReconnectRPCClient
	originalIPs := lastResolvedIPs
	originalResolver := dnsResolver
	originalDNSChecked := values.GetDNSCheckedAfterError()
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		// Restore all original values
		safeReconnectRPCClient = originalSafeReconnectRPCClient
		lastResolvedIPs = originalIPs
		dnsResolver = originalResolver
		values.SetDNSCheckedAfterError(originalDNSChecked)
		values.SetEmergencyMode(originalEmergencyMode)
	}()

	// Setup initial state
	values.SetDNSCheckedAfterError(false)
	values.SetEmergencyMode(false)
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver that returns different IPs on each call
	dnsLookupCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
		_ = host // unused
		dnsLookupCount++
		// Return different IPs each time
		if dnsLookupCount == 1 {
			return makeIPs("192.168.1.2"), nil
		} else {
			return makeIPs("192.168.1.3"), nil
		}
	}
	dnsResolver = mockResolver

	// Create a mock reconnect function that counts calls
	reconnectCount := 0
	safeReconnectRPCClient = func(suppressRegister bool) {
		_ = suppressRegister // unused
		reconnectCount++
	}

	// First call - should check DNS and reconnect
	dnsChanged1, shouldRetry1 := checkAndHandleDNSChange("example.com:8080", false)

	// Verify first call results
	if !dnsChanged1 {
		t.Error("First call: dnsChanged should be true")
	}
	if !shouldRetry1 {
		t.Error("First call: shouldRetry should be true")
	}
	if dnsLookupCount != 1 {
		t.Errorf("First call: DNS lookup count should be 1, got %d", dnsLookupCount)
	}
	if reconnectCount != 1 {
		t.Errorf("First call: reconnect count should be 1, got %d", reconnectCount)
	}
	if !values.GetDNSCheckedAfterError() {
		t.Error("First call: DNS checked flag should be set to true")
	}

	// Second call - should skip DNS check because dnsCheckedAfterError is true
	dnsChanged2, shouldRetry2 := checkAndHandleDNSChange("example.com:8080", false)

	// Verify second call results
	if dnsChanged2 {
		t.Error("Second call: dnsChanged should be false")
	}
	if shouldRetry2 {
		t.Error("Second call: shouldRetry should be false")
	}
	if dnsLookupCount != 1 {
		t.Errorf("Second call: DNS lookup count should still be 1, got %d", dnsLookupCount)
	}
	if reconnectCount != 1 {
		t.Errorf("Second call: reconnect count should still be 1, got %d", reconnectCount)
	}

	// Now simulate a successful login which resets the DNS checked flag
	values.SetDNSCheckedAfterError(false)

	// Third call after successful login - should check DNS again
	dnsChanged3, shouldRetry3 := checkAndHandleDNSChange("example.com:8080", false)

	// Verify third call results
	if !dnsChanged3 {
		t.Error("Third call: dnsChanged should be true")
	}
	if !shouldRetry3 {
		t.Error("Third call: shouldRetry should be true")
	}
	if dnsLookupCount != 2 {
		t.Errorf("Third call: DNS lookup count should be 2, got %d", dnsLookupCount)
	}
	if reconnectCount != 2 {
		t.Errorf("Third call: reconnect count should be 2, got %d", reconnectCount)
	}
	if !values.GetDNSCheckedAfterError() {
		t.Error("Third call: DNS checked flag should be set to true again")
	}
}
