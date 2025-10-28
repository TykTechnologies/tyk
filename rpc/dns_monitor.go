package rpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// DNSMonitor handles background DNS monitoring for worker gateways
type DNSMonitor struct {
	enabled       bool
	checkInterval time.Duration
	connectionStr string
	ctx           context.Context
	cancel        context.CancelFunc
	stopComplete  chan struct{}
}

var (
	// Global DNS monitor instance
	dnsMonitor     *DNSMonitor
	dnsMonitorLock sync.Mutex

	// Prevent concurrent reconnections
	reconnectionInProgress atomic.Value // stores bool
)

// StartDNSMonitor initializes and starts the background DNS monitor
func StartDNSMonitor(enabled bool, checkInterval int, connectionString string) {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	// Stop existing monitor if running
	if dnsMonitor != nil {
		stopDNSMonitorInternal()
	}

	// Initialize/reset reconnection flag
	reconnectionInProgress.Store(false)

	// Don't start if disabled
	if !enabled {
		Log.Debug("DNS monitor is disabled")
		return
	}

	// Validate configuration
	if connectionString == "" {
		Log.Warning("DNS monitor enabled but connection string is empty, skipping monitor start")
		return
	}

	// Set default interval if not specified or invalid
	if checkInterval <= 0 {
		checkInterval = 30 // Default to 30 seconds
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	dnsMonitor = &DNSMonitor{
		enabled:       true,
		checkInterval: time.Duration(checkInterval) * time.Second,
		connectionStr: connectionString,
		ctx:           ctx,
		cancel:        cancel,
		stopComplete:  make(chan struct{}),
	}

	Log.WithFields(logrus.Fields{
		"check_interval": checkInterval,
		"connection":     connectionString,
	}).Info("Starting background DNS monitor for MDCB connection")

	// Start the monitor loop in background
	go dnsMonitor.monitorLoop()
}

// StopDNSMonitor gracefully stops the DNS monitor
func StopDNSMonitor() {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	stopDNSMonitorInternal()
}

// stopDNSMonitorInternal stops the DNS monitor without acquiring the lock
// (assumes caller already holds the lock)
func stopDNSMonitorInternal() {
	if dnsMonitor == nil {
		return
	}

	Log.Info("Stopping background DNS monitor")

	// Signal shutdown
	dnsMonitor.cancel()

	// Wait for monitor loop to complete (with timeout)
	select {
	case <-dnsMonitor.stopComplete:
		Log.Debug("DNS monitor stopped gracefully")
	case <-time.After(5 * time.Second):
		Log.Warning("DNS monitor stop timed out after 5 seconds")
	}

	dnsMonitor = nil
}

// monitorLoop is the main loop that periodically checks DNS
func (m *DNSMonitor) monitorLoop() {
	defer close(m.stopComplete)

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	Log.Debug("DNS monitor loop started")

	for {
		select {
		case <-m.ctx.Done():
			Log.Debug("DNS monitor loop received shutdown signal")
			return
		case <-ticker.C:
			m.checkDNS()
		}
	}
}

// checkDNS performs the DNS check and reconnects if needed
func (m *DNSMonitor) checkDNS() {
	// Don't check if we're in emergency mode
	if values.GetEmergencyMode() {
		Log.Debug("DNS monitor: skipping check (emergency mode active)")
		return
	}

	// Extract hostname from connection string
	host, _, err := net.SplitHostPort(m.connectionStr)
	if err != nil {
		Log.WithError(err).Error("DNS monitor: failed to parse connection string")
		return
	}

	Log.WithField("host", host).Debug("DNS monitor: performing background DNS check")

	// Check if DNS has changed
	changed := updateResolvedIPs(host, dnsResolver)

	if changed {
		Log.Info("DNS monitor: detected DNS change in background, triggering reconnection")

		inProgress := reconnectionInProgress.Load()
		if inProgress != nil && inProgress.(bool) {
			Log.Warning("DNS monitor: reconnection already in progress, skipping duplicate reconnection")
			return
		}

		reconnectionInProgress.Store(true)

		// Reconnect in a separate goroutine to avoid deadlock
		go func() {
			defer func() {
				reconnectionInProgress.Store(false)
			}()

			safeReconnectRPCClient(false)
			Log.Info("DNS monitor: reconnection completed")
		}()
	} else {
		Log.Debug("DNS monitor: no DNS changes detected")
	}
}

// IsDNSMonitorRunning returns whether the DNS monitor is currently running
func IsDNSMonitorRunning() bool {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()
	return dnsMonitor != nil && dnsMonitor.enabled
}
