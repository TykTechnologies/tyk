package rpc

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestDNSMonitorBasicLifecycle tests basic start/stop lifecycle
func TestDNSMonitorBasicLifecycle(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor
	StartDNSMonitor(true, 1, "example.com:8080")

	// Verify monitor is running
	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running after StartDNSMonitor")
	}

	// Stop monitor
	StopDNSMonitor()

	// Verify monitor is stopped
	if IsDNSMonitorRunning() {
		t.Error("DNS monitor should not be running after StopDNSMonitor")
	}
}

// TestDNSMonitorDisabled tests that monitor doesn't start when disabled
func TestDNSMonitorDisabled(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor with disabled=false
	StartDNSMonitor(false, 1, "example.com:8080")

	// Verify monitor is NOT running
	if IsDNSMonitorRunning() {
		t.Error("DNS monitor should not be running when disabled")
	}
}

// TestDNSMonitorEmptyConnectionString tests behavior with empty connection string
func TestDNSMonitorEmptyConnectionString(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor with empty connection string
	StartDNSMonitor(true, 1, "")

	// Verify monitor is NOT running
	if IsDNSMonitorRunning() {
		t.Error("DNS monitor should not start with empty connection string")
	}
}

// TestDNSMonitorDefaultInterval tests that default interval is applied
func TestDNSMonitorDefaultInterval(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor with invalid interval (0)
	StartDNSMonitor(true, 0, "example.com:8080")

	// Verify monitor is running (should use default)
	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running with default interval")
	}

	// Get the monitor instance to check interval
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	if dnsMonitor == nil {
		t.Error("DNS monitor should exist")
		return
	}

	expectedInterval := 30 * time.Second
	if dnsMonitor.baseCheckInterval != expectedInterval {
		t.Errorf("DNS monitor base interval should be %v, got %v", expectedInterval, dnsMonitor.baseCheckInterval)
	}
}

// TestDNSMonitorMinimumInterval tests that minimum interval is enforced
func TestDNSMonitorMinimumInterval(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Try to start monitor with too-low interval (1 second)
	StartDNSMonitor(true, 1, "example.com:8080")

	// Verify monitor is running
	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running with minimum interval")
	}

	// Get the monitor instance to check interval was raised to minimum
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	if dnsMonitor == nil {
		t.Error("DNS monitor should exist")
		return
	}

	minInterval := 10 * time.Second
	if dnsMonitor.baseCheckInterval != minInterval {
		t.Errorf("DNS monitor should enforce minimum interval of %v, got %v", minInterval, dnsMonitor.baseCheckInterval)
	}
}

// TestDNSMonitorProactiveDetection tests proactive DNS change detection
func TestDNSMonitorProactiveDetection(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver that changes IPs after first call
	callCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		callCount++
		if callCount == 1 {
			// First call - return original IP
			return makeIPs("192.168.1.1"), nil
		}
		// Second call onwards - return new IP (DNS changed)
		return makeIPs("192.168.1.2"), nil
	}
	dnsResolver = mockResolver

	// Track reconnect calls
	reconnectCallCount := 0
	var reconnectMu sync.Mutex
	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		defer reconnectMu.Unlock()
		reconnectCallCount++
	}

	// Start monitor with 1 second interval (minimum is now 1s for testing)
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for at least 2 check cycles
	// First check at 1s, then interval doubles to 2s, second check at 3s
	time.Sleep(3500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Verify DNS was checked at least twice
	if callCount < 2 {
		t.Errorf("DNS should have been checked at least 2 times, got %d", callCount)
	}

	// Verify reconnect was called when DNS changed
	reconnectMu.Lock()
	defer reconnectMu.Unlock()
	if reconnectCallCount == 0 {
		t.Error("Reconnect should have been called when DNS changed")
	}
}

// TestDNSMonitorNoDNSChange tests that reconnect is NOT triggered when DNS unchanged
func TestDNSMonitorNoDNSChange(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		StopDNSMonitor()
	}()

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver that always returns the same IP
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		return makeIPs("192.168.1.1"), nil
	}
	dnsResolver = mockResolver

	// Track reconnect calls
	reconnectCallCount := 0
	var reconnectMu sync.Mutex
	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		defer reconnectMu.Unlock()
		reconnectCallCount++
	}

	// Start monitor with very short interval for testing
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for at least 2 check cycles
	time.Sleep(2500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Verify reconnect was NOT called
	reconnectMu.Lock()
	defer reconnectMu.Unlock()
	if reconnectCallCount != 0 {
		t.Errorf("Reconnect should not be called when DNS unchanged, but was called %d times", reconnectCallCount)
	}
}

// TestDNSMonitorGracefulShutdown tests graceful shutdown
func TestDNSMonitorGracefulShutdown(t *testing.T) {
	// Save original values
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
	}()

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		return makeIPs("192.168.1.1"), nil
	}
	dnsResolver = mockResolver

	// Start monitor
	StartDNSMonitor(true, 1, "example.com:8080")

	// Verify monitor is running
	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running")
	}

	// Stop monitor and time the shutdown
	startTime := time.Now()
	StopDNSMonitor()
	shutdownDuration := time.Since(startTime)

	// Verify monitor stopped
	if IsDNSMonitorRunning() {
		t.Error("DNS monitor should be stopped")
	}

	// Verify shutdown was reasonably quick (should be less than 2 seconds)
	if shutdownDuration > 2*time.Second {
		t.Errorf("Shutdown took too long: %v", shutdownDuration)
	}
}

// TestDNSMonitorRestart tests stopping and restarting the monitor
func TestDNSMonitorRestart(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor
	StartDNSMonitor(true, 1, "example.com:8080")

	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running after first start")
	}

	// Stop monitor
	StopDNSMonitor()

	if IsDNSMonitorRunning() {
		t.Error("DNS monitor should be stopped")
	}

	// Restart monitor
	StartDNSMonitor(true, 1, "different.com:9090")

	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running after restart")
	}

	// Verify new connection string is used
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	if dnsMonitor.connectionStr != "different.com:9090" {
		t.Errorf("Expected connection string 'different.com:9090', got '%s'", dnsMonitor.connectionStr)
	}
}

// TestDNSMonitorMultipleStarts tests that starting multiple times doesn't cause issues
func TestDNSMonitorMultipleStarts(t *testing.T) {
	// Clean up after test
	defer StopDNSMonitor()

	// Start monitor multiple times
	StartDNSMonitor(true, 1, "example.com:8080")
	StartDNSMonitor(true, 2, "example.com:8080")
	StartDNSMonitor(true, 3, "example.com:8080")

	// Should only have one monitor running
	if !IsDNSMonitorRunning() {
		t.Error("DNS monitor should be running")
	}

	// Get the monitor to check interval (should be from last start)
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	// Note: 3s is below minimum (10s), so should be raised to 10s
	expectedInterval := 10 * time.Second
	if dnsMonitor.baseCheckInterval != expectedInterval {
		t.Errorf("Expected interval %v (minimum enforced), got %v", expectedInterval, dnsMonitor.baseCheckInterval)
	}
}

// TestDNSMonitorEmergencyMode tests that monitor continues checking DNS even in emergency mode
// This allows recovery when DNS change caused the emergency
func TestDNSMonitorEmergencyMode(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalEmergencyMode := values.GetEmergencyMode()
	originalSafeReconnect := safeReconnectRPCClient
	originalLastReconnectTime := lastReconnectTime
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		values.SetEmergencyMode(originalEmergencyMode)
		safeReconnectRPCClient = originalSafeReconnect
		lastReconnectTime = originalLastReconnectTime
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
		reconnectionInProgress.Store(false)
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs and reset rate limiting
	lastResolvedIPs = []string{"192.168.1.1"}
	lastReconnectMutex.Lock()
	lastReconnectTime = time.Time{} // Reset to zero to allow reconnection
	lastReconnectMutex.Unlock()

	// Set emergency mode to simulate degraded state
	values.SetEmergencyMode(true)

	// Track DNS lookup calls
	callCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		callCount++
		return makeIPs("192.168.1.2"), nil // Different IP - simulates DNS change that could resolve emergency
	}
	dnsResolver = mockResolver

	// Track reconnection attempts
	reconnectCalled := false
	var reconnectMu sync.Mutex
	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		reconnectCalled = true
		reconnectMu.Unlock()
	}

	// Start monitor with 1 second interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for at least 2 check cycles
	// First check at 1s, then interval doubles to 2s, second check at 3s
	time.Sleep(3500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Verify DNS WAS checked even in emergency mode
	if callCount == 0 {
		t.Error("DNS should be checked even in emergency mode to allow recovery from DNS-change-induced emergencies")
	}

	// Verify reconnection was triggered (could pull us out of emergency)
	reconnectMu.Lock()
	defer reconnectMu.Unlock()
	if !reconnectCalled {
		t.Error("Reconnection should be triggered when DNS changes, even in emergency mode")
	}
}

// TestDNSMonitorConcurrentReconnections tests that concurrent reconnections are prevented
func TestDNSMonitorConcurrentReconnections(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalLastReconnectTime := lastReconnectTime
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		lastReconnectTime = originalLastReconnectTime
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
		reconnectionInProgress.Store(false)
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs and reset rate limiting
	lastResolvedIPs = []string{"192.168.1.1"}
	lastReconnectMutex.Lock()
	lastReconnectTime = time.Time{} // Reset to zero to allow reconnection
	lastReconnectMutex.Unlock()

	// Create a mock resolver that always returns different IPs (DNS always changing)
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		// Return a different IP each time to simulate rapid DNS changes
		return makeIPs("192.168.1.100"), nil
	}
	dnsResolver = mockResolver

	// Track reconnect calls with a slow reconnect function
	reconnectCallCount := 0
	var reconnectMu sync.Mutex
	reconnectStarted := make(chan struct{})

	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		reconnectCallCount++
		count := reconnectCallCount
		reconnectMu.Unlock()

		// Signal that first reconnect has started
		if count == 1 {
			close(reconnectStarted)
		}

		// Simulate slow reconnection (longer than check interval)
		time.Sleep(2 * time.Second)
	}

	// Start monitor with 1 second interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for first reconnection to start (will happen at T=1s)
	select {
	case <-reconnectStarted:
		// First reconnection started
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for first reconnection to start")
	}

	// Wait a bit to allow another DNS check while first reconnection is still in progress
	// The reconnection sleeps for 2s, and the next check would be at T=2s (interval doubles to 2s)
	time.Sleep(1500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Verify only ONE reconnection was triggered despite multiple DNS checks
	reconnectMu.Lock()
	defer reconnectMu.Unlock()

	if reconnectCallCount != 1 {
		t.Errorf("Expected exactly 1 reconnection call (concurrent calls should be blocked), got %d", reconnectCallCount)
	}
}

// TestDNSMonitorInvalidConnectionString tests behavior with invalid connection string
func TestDNSMonitorInvalidConnectionString(t *testing.T) {
	// Save original values
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		StopDNSMonitor()
	}()

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver
	callCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		callCount++
		return makeIPs("192.168.1.2"), nil
	}
	dnsResolver = mockResolver

	// Start monitor with invalid connection string (no port)
	StartDNSMonitor(true, 1, "invalid-no-port")

	// Wait for a check cycle
	time.Sleep(1500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// DNS lookup should not have been called due to parsing error
	if callCount > 0 {
		t.Errorf("DNS should not be looked up with invalid connection string, but was checked %d times", callCount)
	}
}

// TestDNSMonitorRateLimiting tests that reconnections are rate limited to prevent flapping
func TestDNSMonitorRateLimiting(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalLastReconnectTime := lastReconnectTime
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		lastReconnectTime = originalLastReconnectTime
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
		reconnectionInProgress.Store(false)
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs and reset rate limiting
	lastResolvedIPs = []string{"192.168.1.1"}
	lastReconnectMutex.Lock()
	lastReconnectTime = time.Time{} // Reset to zero to allow first reconnection
	lastReconnectMutex.Unlock()

	// Create a mock resolver that always returns different IPs (simulating flapping DNS)
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		return makeIPs("192.168.1.100"), nil // Always different
	}
	dnsResolver = mockResolver

	// Track reconnect calls
	reconnectCallCount := 0
	var reconnectMu sync.Mutex

	// Use instant reconnect (no delay) for testing
	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		reconnectCallCount++
		reconnectMu.Unlock()
		time.Sleep(100 * time.Millisecond) // Small delay to simulate reconnection
	}

	// Start monitor with 1 second interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for first reconnection to complete (1s + buffer)
	time.Sleep(1500 * time.Millisecond)

	// Get reconnect count after first cycle
	reconnectMu.Lock()
	firstCount := reconnectCallCount
	reconnectMu.Unlock()

	// First reconnection should have happened
	if firstCount == 0 {
		t.Error("Expected at least one reconnection, got none")
	}

	// Wait for more check cycles (DNS still shows changes but should be rate limited)
	// Next check at 2s (interval doubled), but rate limiting should block reconnection
	time.Sleep(2 * time.Second)

	// Stop monitor
	StopDNSMonitor()

	// Get final reconnect count
	reconnectMu.Lock()
	finalCount := reconnectCallCount
	reconnectMu.Unlock()

	// Should still be 1 due to rate limiting (60 second window)
	// Even though DNS kept changing, reconnections should be blocked
	if finalCount > 1 {
		t.Errorf("Expected reconnection to be rate limited (max 1), but got %d reconnections", finalCount)
	}
}

// TestDNSMonitorRateLimitingSurvivesRestart tests that rate limiting persists across monitor restarts
func TestDNSMonitorRateLimitingSurvivesRestart(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient
	originalLastReconnectTime := lastReconnectTime
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		lastReconnectTime = originalLastReconnectTime
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
		reconnectionInProgress.Store(false)
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs and reset rate limiting
	lastResolvedIPs = []string{"192.168.1.1"}
	lastReconnectMutex.Lock()
	lastReconnectTime = time.Time{} // Reset to zero to allow first reconnection
	lastReconnectMutex.Unlock()

	// Create a mock resolver that always returns different IPs
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		return makeIPs("192.168.1.100"), nil // Always different
	}
	dnsResolver = mockResolver

	// Track reconnect calls
	reconnectCallCount := 0
	var reconnectMu sync.Mutex

	safeReconnectRPCClient = func(_ bool) {
		reconnectMu.Lock()
		reconnectCallCount++
		reconnectMu.Unlock()
	}

	// Start monitor with 1 second interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for first reconnection to trigger (1s + buffer)
	time.Sleep(1500 * time.Millisecond)

	// Get first count
	reconnectMu.Lock()
	firstCount := reconnectCallCount
	reconnectMu.Unlock()

	if firstCount == 0 {
		t.Error("Expected at least one reconnection")
	}

	// Stop and restart monitor (simulating what happens during reconnection)
	StopDNSMonitor()
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for more check cycles
	// First check at 1s, interval doubles to 2s, second check at 3s
	time.Sleep(3500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Get final count
	reconnectMu.Lock()
	finalCount := reconnectCallCount
	reconnectMu.Unlock()

	// Should still be 1 because rate limiting state survived the restart
	if finalCount > 1 {
		t.Errorf("Expected rate limiting to survive restart (max 1 reconnection), but got %d", finalCount)
	}
}

// TestDNSMonitorExponentialBackoff tests that check interval grows exponentially when DNS is stable
func TestDNSMonitorExponentialBackoff(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalMinInterval := minCheckInterval

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		minCheckInterval = originalMinInterval
		StopDNSMonitor()
	}()

	// Set minimum interval to 1 second for faster testing
	minCheckInterval = 1

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver that returns same IPs (no DNS change)
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		return makeIPs("192.168.1.1"), nil // Always same
	}
	dnsResolver = mockResolver

	// Start monitor with 1 second base interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Get monitor instance to check intervals
	dnsMonitorLock.Lock()
	if dnsMonitor == nil {
		dnsMonitorLock.Unlock()
		t.Fatal("DNS monitor should be running")
	}

	// Verify initial interval is base interval
	dnsMonitor.intervalMutex.Lock()
	initialInterval := dnsMonitor.currentInterval
	baseInterval := dnsMonitor.baseCheckInterval
	maxInterval := dnsMonitor.maxCheckInterval
	dnsMonitor.intervalMutex.Unlock()
	dnsMonitorLock.Unlock()

	if initialInterval != baseInterval {
		t.Errorf("Initial interval should be %v, got %v", baseInterval, initialInterval)
	}

	if maxInterval != 10*time.Minute {
		t.Errorf("Max interval should be 10 minutes, got %v", maxInterval)
	}

	// Wait for first check to complete and interval to grow (1s + buffer)
	time.Sleep(1200 * time.Millisecond)

	dnsMonitorLock.Lock()
	dnsMonitor.intervalMutex.Lock()
	intervalAfterFirstCheck := dnsMonitor.currentInterval
	dnsMonitor.intervalMutex.Unlock()
	dnsMonitorLock.Unlock()

	// Should have doubled: 1s → 2s
	expectedAfterFirst := 2 * time.Second
	if intervalAfterFirstCheck != expectedAfterFirst {
		t.Errorf("After first check, interval should be %v, got %v", expectedAfterFirst, intervalAfterFirstCheck)
	}

	// Wait for next check (should happen at 2s interval)
	time.Sleep(2200 * time.Millisecond)

	dnsMonitorLock.Lock()
	dnsMonitor.intervalMutex.Lock()
	intervalAfterSecondCheck := dnsMonitor.currentInterval
	dnsMonitor.intervalMutex.Unlock()
	dnsMonitorLock.Unlock()

	// Should have doubled again: 2s → 4s
	expectedAfterSecond := 4 * time.Second
	if intervalAfterSecondCheck != expectedAfterSecond {
		t.Errorf("After second check, interval should be %v, got %v", expectedAfterSecond, intervalAfterSecondCheck)
	}

	// Stop monitor
	StopDNSMonitor()

	t.Logf("Exponential backoff verified: %v → %v → %v", baseInterval, intervalAfterFirstCheck, intervalAfterSecondCheck)
}

// TestDNSMonitorBackoffResetOnChange tests that interval resets to base when DNS changes
func TestDNSMonitorBackoffResetOnChange(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalSafeReconnect := safeReconnectRPCClient

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		safeReconnectRPCClient = originalSafeReconnect
		StopDNSMonitor()
		reconnectionInProgress.Store(false)
	}()

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Create a mock resolver that changes behavior
	shouldChange := false
	var changeMu sync.Mutex
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(_ string) ([]net.IP, error) {
		changeMu.Lock()
		defer changeMu.Unlock()
		if shouldChange {
			return makeIPs("192.168.1.2"), nil // Changed
		}
		return makeIPs("192.168.1.1"), nil // Same
	}
	dnsResolver = mockResolver

	// Mock reconnect to avoid actual reconnection
	safeReconnectRPCClient = func(_ bool) {
		// Do nothing
	}

	// Start monitor with 1 second base interval
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for interval to grow (1s → 2s)
	time.Sleep(1500 * time.Millisecond)

	dnsMonitorLock.Lock()
	dnsMonitor.intervalMutex.Lock()
	intervalBeforeChange := dnsMonitor.currentInterval
	dnsMonitor.intervalMutex.Unlock()
	dnsMonitorLock.Unlock()

	if intervalBeforeChange != 2*time.Second {
		t.Logf("Warning: interval before change is %v, expected 2s", intervalBeforeChange)
	}

	// Now trigger a DNS change
	changeMu.Lock()
	shouldChange = true
	changeMu.Unlock()

	// Wait for next check to detect change and reset interval
	time.Sleep(2500 * time.Millisecond)

	dnsMonitorLock.Lock()
	dnsMonitor.intervalMutex.Lock()
	intervalAfterChange := dnsMonitor.currentInterval
	baseInterval := dnsMonitor.baseCheckInterval
	dnsMonitor.intervalMutex.Unlock()
	dnsMonitorLock.Unlock()

	// Should have reset to base interval
	if intervalAfterChange != baseInterval {
		t.Errorf("After DNS change, interval should reset to base (%v), got %v", baseInterval, intervalAfterChange)
	}

	// Stop monitor
	StopDNSMonitor()

	t.Logf("Interval reset verified: grew to %v, then reset to %v after DNS change", intervalBeforeChange, intervalAfterChange)
}
