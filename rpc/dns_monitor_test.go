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
	if dnsMonitor.checkInterval != expectedInterval {
		t.Errorf("DNS monitor interval should be %v, got %v", expectedInterval, dnsMonitor.checkInterval)
	}
}

// TestDNSMonitorProactiveDetection tests proactive DNS change detection
func TestDNSMonitorProactiveDetection(t *testing.T) {
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

	// Create a mock resolver that changes IPs after first call
	callCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
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
	safeReconnectRPCClient = func(suppressRegister bool) {
		reconnectMu.Lock()
		defer reconnectMu.Unlock()
		reconnectCallCount++
	}

	// Start monitor with very short interval for testing
	StartDNSMonitor(true, 1, "example.com:8080") // 1 second interval

	// Wait for at least 2 check cycles
	time.Sleep(2500 * time.Millisecond)

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
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
		return makeIPs("192.168.1.1"), nil
	}
	dnsResolver = mockResolver

	// Track reconnect calls
	reconnectCallCount := 0
	var reconnectMu sync.Mutex
	safeReconnectRPCClient = func(suppressRegister bool) {
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
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
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

	if dnsMonitor.checkInterval != 3*time.Second {
		t.Errorf("Expected interval 3s, got %v", dnsMonitor.checkInterval)
	}
}

// TestDNSMonitorEmergencyMode tests that monitor skips checks in emergency mode
func TestDNSMonitorEmergencyMode(t *testing.T) {
	// Save original values and restore after test
	originalResolver := dnsResolver
	originalIPs := lastResolvedIPs
	originalEmergencyMode := values.GetEmergencyMode()

	defer func() {
		dnsResolver = originalResolver
		lastResolvedIPs = originalIPs
		values.SetEmergencyMode(originalEmergencyMode)
		StopDNSMonitor()
	}()

	// Set initial IPs
	lastResolvedIPs = []string{"192.168.1.1"}

	// Set emergency mode
	values.SetEmergencyMode(true)

	// Track DNS lookup calls
	callCount := 0
	mockResolver := &MockDNSResolver{}
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
		callCount++
		return makeIPs("192.168.1.2"), nil // Different IP
	}
	dnsResolver = mockResolver

	// Start monitor
	StartDNSMonitor(true, 1, "example.com:8080")

	// Wait for a few check cycles
	time.Sleep(2500 * time.Millisecond)

	// Stop monitor
	StopDNSMonitor()

	// Verify DNS was NOT checked (emergency mode should skip checks)
	if callCount > 0 {
		t.Errorf("DNS should not be checked in emergency mode, but was checked %d times", callCount)
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
	mockResolver.LookupIPFunc = func(host string) ([]net.IP, error) {
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
