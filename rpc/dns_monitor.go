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
	enabled           bool
	baseCheckInterval time.Duration // T0 - minimum interval (e.g., 30s)
	maxCheckInterval  time.Duration // Tmax - maximum interval (e.g., 10min)
	currentInterval   time.Duration // Current interval (grows with exponential backoff)
	connectionStr     string
	ctx               context.Context
	cancel            context.CancelFunc
	stopComplete      chan struct{}
	intervalMutex     sync.Mutex // Protects currentInterval
}

var (
	// Global DNS monitor instance
	dnsMonitor     *DNSMonitor
	dnsMonitorLock sync.Mutex

	// Prevent concurrent reconnections - global state independent of monitor lifecycle
	reconnectionInProgress atomic.Bool

	// Rate limiting state - global to survive monitor restarts during reconnection
	lastReconnectTime  time.Time
	lastReconnectMutex sync.Mutex
)

// StartDNSMonitor initializes and starts the background DNS monitor
func StartDNSMonitor(enabled bool, checkInterval int, connectionString string) {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()

	// Stop existing monitor if running
	if dnsMonitor != nil {
		stopDNSMonitorInternal()
	}

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

	// Validate and set interval with minimum threshold
	const minInterval = 10 // Minimum 10 seconds to prevent DNS server overload
	if checkInterval <= 0 {
		checkInterval = 30 // Default to 30 seconds
	} else if checkInterval < minInterval {
		Log.WithFields(logrus.Fields{
			"requested_interval": checkInterval,
			"minimum_interval":   minInterval,
		}).Warning("DNS monitor: check interval too low, using minimum")
		checkInterval = minInterval
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	baseInterval := time.Duration(checkInterval) * time.Second
	maxInterval := 10 * time.Minute

	dnsMonitor = &DNSMonitor{
		enabled:           true,
		baseCheckInterval: baseInterval,
		maxCheckInterval:  maxInterval,
		currentInterval:   baseInterval, // Start with base interval
		connectionStr:     connectionString,
		ctx:               ctx,
		cancel:            cancel,
		stopComplete:      make(chan struct{}),
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

// monitorLoop is the main loop that periodically checks DNS with exponential backoff
func (m *DNSMonitor) monitorLoop() {
	defer close(m.stopComplete)

	// Start with base interval
	m.intervalMutex.Lock()
	currentInterval := m.currentInterval
	m.intervalMutex.Unlock()

	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	Log.WithField("initial_interval", currentInterval).Debug("DNS monitor loop started with exponential backoff")

	for {
		select {
		case <-m.ctx.Done():
			Log.Debug("DNS monitor loop received shutdown signal")
			return
		case <-ticker.C:
			changed := m.checkDNS()

			// Update interval based on whether DNS changed
			m.intervalMutex.Lock()
			if changed {
				// Reset to base interval when change detected
				m.currentInterval = m.baseCheckInterval
				Log.WithField("new_interval", m.currentInterval).Info("DNS monitor: DNS changed, reset interval to base")
			} else {
				// Double the interval (exponential backoff), but cap at max
				newInterval := m.currentInterval * 2
				if newInterval > m.maxCheckInterval {
					newInterval = m.maxCheckInterval
				}
				if newInterval != m.currentInterval {
					m.currentInterval = newInterval
					Log.WithField("new_interval", m.currentInterval).Debug("DNS monitor: no change, increased check interval")
				}
			}
			currentInterval = m.currentInterval
			m.intervalMutex.Unlock()

			// Reset ticker with new interval
			ticker.Reset(currentInterval)
		}
	}
}

// checkDNS performs the DNS check and reconnects if needed
// Returns true if DNS changed, false otherwise
func (m *DNSMonitor) checkDNS() bool {
	// Extract hostname from connection string
	host, _, err := net.SplitHostPort(m.connectionStr)
	if err != nil {
		Log.WithError(err).Error("DNS monitor: failed to parse connection string")
		return false
	}

	Log.WithField("host", host).Debug("DNS monitor: performing background DNS check")

	// Check if DNS has changed (pass monitor context for cancellation support)
	changed := updateResolvedIPs(m.ctx, host, dnsResolver)

	if !changed {
		Log.Debug("DNS monitor: no DNS changes detected")
		return false
	}

	if changed {
		Log.Info("DNS monitor: detected DNS change in background, triggering reconnection")

		// Try to atomically set reconnection flag from false to true
		// If already true, another reconnection is in progress, so skip
		if !reconnectionInProgress.CompareAndSwap(false, true) {
			Log.Warning("DNS monitor: reconnection already in progress, skipping duplicate reconnection")
			return true // DNS did change, even though we skipped reconnection
		}

		// Check rate limiting - prevent reconnections within 60 seconds
		// Use global rate-limiting state that survives monitor restarts
		lastReconnectMutex.Lock()
		timeSinceLastReconnect := time.Since(lastReconnectTime)
		rateLimitWindow := 60 * time.Second

		if timeSinceLastReconnect < rateLimitWindow && !lastReconnectTime.IsZero() {
			lastReconnectMutex.Unlock()
			reconnectionInProgress.Store(false)
			Log.WithFields(logrus.Fields{
				"time_since_last": timeSinceLastReconnect.Seconds(),
				"rate_limit":      rateLimitWindow.Seconds(),
			}).Warning("DNS monitor: reconnection rate limited, skipping to prevent flapping")
			return true // DNS did change, even though we skipped reconnection
		}

		lastReconnectTime = time.Now()
		lastReconnectMutex.Unlock()

		// Reconnect in a separate goroutine to avoid deadlock
		go func() {
			defer func() {
				reconnectionInProgress.Store(false)
			}()

			safeReconnectRPCClient(false)
			Log.Info("DNS monitor: reconnection completed")
		}()

		return true // DNS changed and reconnection initiated
	}

	return false
}

// IsDNSMonitorRunning returns whether the DNS monitor is currently running
func IsDNSMonitorRunning() bool {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()
	return dnsMonitor != nil && dnsMonitor.enabled
}
