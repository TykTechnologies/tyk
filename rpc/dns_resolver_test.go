package rpc

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockDNSResolver for testing DNS functionality
type mockDNSResolverRPC struct {
	mu       sync.RWMutex
	ipMap    map[string][]string
	fails    bool
	callLog  []string
	failNext int
}

func newMockDNSResolverRPC() *mockDNSResolverRPC {
	return &mockDNSResolverRPC{
		ipMap:   make(map[string][]string),
		callLog: make([]string, 0),
	}
}

func (m *mockDNSResolverRPC) LookupIP(host string) ([]net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callLog = append(m.callLog, host)

	if m.failNext > 0 {
		m.failNext--
		return nil, errors.New("simulated DNS resolution failure")
	}

	if m.fails {
		return nil, errors.New("DNS server is down")
	}

	ipStrings, exists := m.ipMap[host]
	if !exists {
		return nil, errors.New("host not found")
	}

	ips := make([]net.IP, len(ipStrings))
	for i, ipStr := range ipStrings {
		ips[i] = net.ParseIP(ipStr)
	}

	return ips, nil
}

func (m *mockDNSResolverRPC) setIP(host string, ips ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipMap[host] = ips
}

func (m *mockDNSResolverRPC) setFails(fails bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fails = fails
}

func (m *mockDNSResolverRPC) setFailNext(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext = count
}

func (m *mockDNSResolverRPC) getCallLog() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.callLog))
	copy(result, m.callLog)
	return result
}

func (m *mockDNSResolverRPC) clearCallLog() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callLog = m.callLog[:0]
}

// TestDNSResolutionChangeDetection tests the core DNS change detection functionality
func TestDNSResolutionChangeDetection(t *testing.T) {
	// Save original resolver
	originalResolver := dnsResolver
	defer func() { dnsResolver = originalResolver }()

	mockResolver := newMockDNSResolverRPC()
	dnsResolver = mockResolver

	// Test 1: Initial DNS resolution
	mockResolver.setIP("test.host", "127.0.0.1")
	
	changed := updateResolvedIPs("test.host", mockResolver)
	assert.True(t, changed, "Initial DNS resolution should register as changed")

	callLog := mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should have made one DNS call")
	assert.Equal(t, "test.host", callLog[0], "Should have resolved the correct host")

	// Test 2: Same IP resolution (no change)
	mockResolver.clearCallLog()
	changed = updateResolvedIPs("test.host", mockResolver)
	assert.False(t, changed, "Same IP resolution should not register as changed")

	// Test 3: IP change detection
	mockResolver.clearCallLog()
	mockResolver.setIP("test.host", "127.0.0.2")
	
	changed = updateResolvedIPs("test.host", mockResolver)
	assert.True(t, changed, "IP change should be detected")

	callLog = mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should have made one DNS call for change detection")

	// Test 4: Multiple IP resolution
	mockResolver.clearCallLog()
	mockResolver.setIP("test.host", "127.0.0.1", "127.0.0.2", "127.0.0.3")
	
	changed = updateResolvedIPs("test.host", mockResolver)
	assert.True(t, changed, "Multiple IP change should be detected")

	// Test 5: DNS resolution failure
	mockResolver.clearCallLog()
	mockResolver.setFails(true)
	
	changed = updateResolvedIPs("test.host", mockResolver)
	assert.False(t, changed, "DNS failure should not register as change")

	callLog = mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should have attempted DNS resolution even on failure")
}

// TestDNSThrottlingMechanism tests the DNS check throttling
func TestDNSThrottlingMechanism(t *testing.T) {
	// Save original state
	originalResolver := dnsResolver
	originalReconnectFunc := safeReconnectRPCClient
	defer func() { 
		dnsResolver = originalResolver
		safeReconnectRPCClient = originalReconnectFunc
	}()

	// Mock the reconnection function to avoid RPC setup
	reconnectCalled := false
	safeReconnectRPCClient = func(suppressRegister bool) {
		reconnectCalled = true
	}

	// Reset RPC state for clean test
	values.Reset()
	defer values.Reset()

	mockResolver := newMockDNSResolverRPC()
	dnsResolver = mockResolver
	mockResolver.setIP("test.host", "127.0.0.1")

	// Test 1: First DNS check after error should proceed
	values.SetDNSCheckedAfterError(false)
	values.SetEmergencyMode(false)
	
	// Set up initial resolved IPs to have a baseline
	updateResolvedIPs("test.host", mockResolver)
	mockResolver.clearCallLog()
	
	dnsChanged, shouldRetry := checkAndHandleDNSChange("test.host:8080", true)
	
	assert.True(t, values.GetDNSCheckedAfterError(), "DNS checked flag should be set after first check")
	callLog := mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should have made DNS call on first check")

	// Test 2: Subsequent DNS checks should be throttled
	mockResolver.clearCallLog()
	reconnectCalled = false
	dnsChanged, shouldRetry = checkAndHandleDNSChange("test.host:8080", true)
	
	assert.False(t, dnsChanged, "Subsequent check should be throttled")
	assert.False(t, shouldRetry, "Should not retry when throttled")
	callLog = mockResolver.getCallLog()
	assert.Len(t, callLog, 0, "Should not make DNS call when throttled")
	assert.False(t, reconnectCalled, "Should not trigger reconnect when throttled")

	// Test 3: Reset throttling flag allows new DNS check
	values.SetDNSCheckedAfterError(false)
	mockResolver.clearCallLog()
	mockResolver.setIP("test.host", "127.0.0.2") // Change IP to trigger change detection
	reconnectCalled = false
	
	dnsChanged, shouldRetry = checkAndHandleDNSChange("test.host:8080", true)
	
	callLog = mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should make DNS call after reset")
	assert.True(t, reconnectCalled, "Should trigger reconnect when DNS change detected")
}

// TestDNSRecoveryScenarios tests various DNS recovery scenarios
func TestDNSRecoveryScenarios(t *testing.T) {
	// Save original state
	originalResolver := dnsResolver
	defer func() { dnsResolver = originalResolver }()

	mockResolver := newMockDNSResolverRPC()
	dnsResolver = mockResolver

	scenarios := []struct {
		name           string
		setupDNS       func()
		expectChange   bool
		expectCalls    int
	}{
		{
			name: "IP address change",
			setupDNS: func() {
				// First establish baseline
				mockResolver.setIP("service.test", "127.0.0.1")
				updateResolvedIPs("service.test", mockResolver)
				mockResolver.clearCallLog()
				// Then change IP
				mockResolver.setIP("service.test", "127.0.0.2")
			},
			expectChange: true,
			expectCalls:  1,
		},
		{
			name: "DNS server temporary failure",
			setupDNS: func() {
				// Establish baseline
				mockResolver.setIP("service.test", "127.0.0.1")
				updateResolvedIPs("service.test", mockResolver)
				mockResolver.clearCallLog()
				// Simulate DNS failure
				mockResolver.setFails(true)
			},
			expectChange: false,
			expectCalls:  1,
		},
		{
			name: "Load balancer IP rotation",
			setupDNS: func() {
				// Start with single IP
				mockResolver.setIP("lb.test", "127.0.0.1")
				updateResolvedIPs("lb.test", mockResolver)
				mockResolver.clearCallLog()
				// Add more IPs (load balancer scenario)
				mockResolver.setIP("lb.test", "127.0.0.1", "127.0.0.2", "127.0.0.3")
			},
			expectChange: true,
			expectCalls:  1,
		},
		{
			name: "No change scenario",
			setupDNS: func() {
				// Establish baseline
				mockResolver.setIP("stable.test", "127.0.0.1")
				updateResolvedIPs("stable.test", mockResolver)
				mockResolver.clearCallLog()
				// Call again with same IP
			},
			expectChange: false,
			expectCalls:  1,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Setup the DNS scenario
			scenario.setupDNS()

			// Test the DNS resolution
			var changed bool
			if scenario.name == "No change scenario" {
				changed = updateResolvedIPs("stable.test", mockResolver)
			} else if scenario.name == "Load balancer IP rotation" {
				changed = updateResolvedIPs("lb.test", mockResolver)
			} else {
				changed = updateResolvedIPs("service.test", mockResolver)
			}

			// Verify results
			assert.Equal(t, scenario.expectChange, changed, "DNS change detection should match expected result")
			
			callLog := mockResolver.getCallLog()
			assert.Equal(t, scenario.expectCalls, len(callLog), "Number of DNS calls should match expected")

			// Reset for next test
			mockResolver.setFails(false)
		})
	}
}

// TestNetworkErrorDetection tests the network error classification
func TestNetworkErrorDetection(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "timeout error",
			err:      errors.New("Cannot obtain response during timeout=30s"),
			expected: true,
		},
		{
			name:     "unexpected response error",
			err:      errors.New("unexpected response type: <nil>. Expected *dispatcherResponse"),
			expected: true,
		},
		{
			name:     "rpc down error",
			err:      errors.New("rpc is either down or was not configured"),
			expected: true,
		},
		{
			name:     "decode error",
			err:      errors.New("Cannot decode response"),
			expected: true,
		},
		{
			name:     "non-network error",
			err:      errors.New("Access Denied"),
			expected: false,
		},
		{
			name:     "random error",
			err:      errors.New("some other error"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isNetworkError(tc.err)
			assert.Equal(t, tc.expected, result, "Network error detection should match expected result")
		})
	}
}

// TestDNSChangeWithEmergencyMode tests DNS behavior during emergency mode
func TestDNSChangeWithEmergencyMode(t *testing.T) {
	// Save original state
	originalResolver := dnsResolver
	originalReconnectFunc := safeReconnectRPCClient
	defer func() { 
		dnsResolver = originalResolver
		safeReconnectRPCClient = originalReconnectFunc
	}()

	// Mock the reconnection function
	safeReconnectRPCClient = func(suppressRegister bool) {
		// Do nothing for test
	}

	// Reset state
	values.Reset()
	defer values.Reset()

	mockResolver := newMockDNSResolverRPC()
	dnsResolver = mockResolver
	mockResolver.setIP("emergency.test", "127.0.0.1")

	// Test 1: Normal mode allows DNS checks
	values.SetEmergencyMode(false)
	values.SetDNSCheckedAfterError(false)
	
	// Set up baseline
	updateResolvedIPs("emergency.test", mockResolver)
	mockResolver.clearCallLog()
	
	dnsChanged, shouldRetry := checkAndHandleDNSChange("emergency.test:8080", true)
	callLog := mockResolver.getCallLog()
	assert.Len(t, callLog, 1, "Should make DNS call in normal mode")

	// Test 2: Emergency mode blocks DNS checks
	mockResolver.clearCallLog()
	values.SetEmergencyMode(true)
	values.SetDNSCheckedAfterError(false) // Reset flag
	
	dnsChanged, shouldRetry = checkAndHandleDNSChange("emergency.test:8080", true)
	assert.False(t, dnsChanged, "Emergency mode should block DNS change detection")
	assert.False(t, shouldRetry, "Should not retry in emergency mode")
	
	callLog = mockResolver.getCallLog()
	assert.Len(t, callLog, 0, "Should not make DNS call in emergency mode")
}

// TestHandleRPCErrorWithDNS tests the RPC error handling that triggers DNS checks
func TestHandleRPCErrorWithDNS(t *testing.T) {
	// Save original state
	originalResolver := dnsResolver
	originalReconnectFunc := safeReconnectRPCClient
	defer func() { 
		dnsResolver = originalResolver
		safeReconnectRPCClient = originalReconnectFunc
	}()

	// Mock the reconnection function
	safeReconnectRPCClient = func(suppressRegister bool) {
		// Do nothing for test
	}

	values.Reset()
	defer values.Reset()

	mockResolver := newMockDNSResolverRPC()
	dnsResolver = mockResolver
	mockResolver.setIP("rpc.test", "127.0.0.1")

	testCases := []struct {
		name                 string
		err                  error
		expectedDNSCalls     int
		expectedRetryResult  bool
	}{
		{
			name:                "network error triggers DNS check",
			err:                 errors.New("Cannot obtain response during timeout=30s"),
			expectedDNSCalls:    1,
			expectedRetryResult: false, // No change detected, so no retry
		},
		{
			name:                "non-network error skips DNS check",
			err:                 errors.New("Access Denied"),
			expectedDNSCalls:    0,
			expectedRetryResult: false,
		},
		{
			name:                "nil error skips DNS check",
			err:                 nil,
			expectedDNSCalls:    0,
			expectedRetryResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset state for each test
			values.SetDNSCheckedAfterError(false)
			values.SetEmergencyMode(false)
			mockResolver.clearCallLog()

			// Set up baseline for DNS if it's a network error test
			if tc.expectedDNSCalls > 0 {
				updateResolvedIPs("rpc.test", mockResolver)
				mockResolver.clearCallLog()
			}

			// Test the error handling
			shouldRetry := handleRPCError(tc.err, "rpc.test:8080")
			
			assert.Equal(t, tc.expectedRetryResult, shouldRetry, "Retry decision should match expected")
			
			callLog := mockResolver.getCallLog()
			assert.Equal(t, tc.expectedDNSCalls, len(callLog), "Number of DNS calls should match expected")
		})
	}
}