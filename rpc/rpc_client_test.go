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

// MockDNSResolver implements DNSResolver for testing
type MockDNSResolver struct {
	LookupIPFunc func(host string) ([]net.IP, error)
}

func (m *MockDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return m.LookupIPFunc(host)
}

// Helper function to create IP addresses for testing
func makeIPs(ips ...string) []net.IP {
	result := make([]net.IP, len(ips))
	for i, ip := range ips {
		result[i] = net.ParseIP(ip)
	}
	return result
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
				return tt.resolvedIPs, tt.resolveError
			}

			// Call the function
			result := updateResolvedIPs("example.com", mockResolver)

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
