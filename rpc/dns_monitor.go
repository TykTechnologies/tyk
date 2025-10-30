package rpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/sirupsen/logrus"
)

// DNSMonitor handles background DNS monitoring for worker gateways
type DNSMonitor struct {
	enabled           bool
	baseCheckInterval time.Duration // T0 - minimum interval (e.g., 30s)
	maxCheckInterval  time.Duration // Tmax - maximum interval (e.g., 10min)
	connectionStr     string
	ctx               context.Context
	cancel            context.CancelFunc
	stopComplete      chan struct{}
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

	// minCheckInterval is the minimum interval in seconds (can be overridden in tests)
	minCheckInterval = 10
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
	const recommendedMinInterval = 30 // Recommended to avoid DNS server rate limiting

	if checkInterval <= 0 {
		checkInterval = recommendedMinInterval // Default to 30 seconds
		Log.WithField("interval", checkInterval).Debug("DNS monitor: using default check interval")
	} else if checkInterval < minCheckInterval {
		Log.WithFields(logrus.Fields{
			"requested_interval": checkInterval,
			"minimum_interval":   minCheckInterval,
		}).Warning("DNS monitor: check interval too low, using minimum to prevent DNS server overload")
		checkInterval = minCheckInterval
	} else if checkInterval < recommendedMinInterval {
		Log.WithFields(logrus.Fields{
			"current_interval":     checkInterval,
			"recommended_interval": recommendedMinInterval,
		}).Warning("DNS monitor: check interval is below recommended minimum. Consider using 30s or higher to avoid DNS server rate limiting")
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	baseInterval := time.Duration(checkInterval) * time.Second
	maxInterval := 10 * time.Minute

	dnsMonitor = &DNSMonitor{
		enabled:           true,
		baseCheckInterval: baseInterval,
		maxCheckInterval:  maxInterval,
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

	// Configure exponential backoff
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = m.baseCheckInterval   // T0 (e.g., 30s)
	b.MaxInterval = m.maxCheckInterval        // Tmax (e.g., 10 min)
	b.MaxElapsedTime = 0                      // Never stop (no total timeout)
	b.Multiplier = 2.0                        // Simple doubling
	b.RandomizationFactor = 0                 // No jitter (set to 0.1 if you want some)
	b.Reset()

	// Get initial interval
	currentInterval := b.NextBackOff()
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

			if changed {
				// Reset to base interval when change detected
				b.Reset()
				currentInterval = b.NextBackOff()
				Log.WithField("new_interval", currentInterval).Info("DNS monitor: DNS changed, reset interval to base")
			} else {
				// Get next interval (exponential backoff with cap)
				currentInterval = b.NextBackOff()
				Log.WithField("new_interval", currentInterval).Debug("DNS monitor: no change, increased check interval")
			}

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

	// Check if DNS has changed WITHOUT updating cache yet (pass monitor context for cancellation support)
	// We only update cached IPs after successfully acquiring the reconnection lock
	changed, newIPs, err := checkDNSChanged(m.ctx, host, dnsResolver)
	if err != nil || !changed {
		if !changed {
			Log.Debug("DNS monitor: no DNS changes detected")
		}
		return false
	}

	Log.Info("DNS monitor: detected DNS change in background, triggering reconnection")

	// Try to atomically set reconnection flag from false to true
	// If already true, another reconnection is in progress, so skip
	// IMPORTANT: Don't update cache if we can't acquire the lock
	if !reconnectionInProgress.CompareAndSwap(false, true) {
		Log.Warning("DNS monitor: reconnection already in progress, skipping duplicate reconnection")
		// Don't update cached IPs since we're not reconnecting
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
		// Don't update cached IPs since we're not reconnecting
		return true // DNS did change, even though we skipped reconnection
	}

	lastReconnectTime = time.Now()
	lastReconnectMutex.Unlock()

	// Update cached IPs now that we've acquired the lock and passed rate limiting
	updateCachedIPs(newIPs)

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

// IsDNSMonitorRunning returns whether the DNS monitor is currently running
func IsDNSMonitorRunning() bool {
	dnsMonitorLock.Lock()
	defer dnsMonitorLock.Unlock()
	return dnsMonitor != nil && dnsMonitor.enabled
}
