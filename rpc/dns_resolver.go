package rpc

import (
	"context"
	"net"
	"sync"
)

var (
	// for dns monitoring
	lastResolvedIPs []string
	dnsRefreshMutex sync.RWMutex

	// global resolver to be replaced in tests
	dnsResolver DNSResolver = &DefaultDNSResolver{}

	// declare funcs as vars that we can override in testing
	safeReconnectRPCClient func(suppressRegister bool)
)

//nolint:gochecknoinits
func init() {
	safeReconnectRPCClient = defaultSafeReconnectRPCClient
}

// DNSResolver provides methods for DNS resolution
type DNSResolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// DefaultDNSResolver implements DNSResolver using the standard library
type DefaultDNSResolver struct{}

func (r *DefaultDNSResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	resolver := &net.Resolver{}
	return resolver.LookupIP(ctx, "ip", host)
}

// checkDNSChanged checks if DNS resolution has changed WITHOUT updating the cached IPs
// Returns: changed bool, newIPs []string, error
func checkDNSChanged(ctx context.Context, host string, resolver DNSResolver) (bool, []string, error) {
	ips, err := resolver.LookupIP(ctx, host)
	if err != nil {
		Log.Error("Failed to resolve host during DNS refresh:", err)
		return false, nil, err
	}

	// Extract IPv4 addresses
	newIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			newIPs = append(newIPs, ipv4.String())
		}
	}

	dnsRefreshMutex.Lock()
	changed := !equalStringSlices(lastResolvedIPs, newIPs)
	dnsRefreshMutex.Unlock()

	return changed, newIPs, nil
}

// updateCachedIPs updates the cached resolved IPs
func updateCachedIPs(newIPs []string) {
	dnsRefreshMutex.Lock()
	defer dnsRefreshMutex.Unlock()
	Log.Debug("DNS resolution changed from", lastResolvedIPs, "to", newIPs)
	lastResolvedIPs = newIPs
}

// updateResolvedIPs checks if DNS resolution has changed and updates cached IPs if so
func updateResolvedIPs(ctx context.Context, host string, resolver DNSResolver) bool {
	changed, newIPs, err := checkDNSChanged(ctx, host, resolver)
	if err != nil {
		return false
	}

	if changed {
		updateCachedIPs(newIPs)
	}

	return changed
}

// checkDNSAndReconnect checks if DNS resolution has changed and reconnects if needed
func checkDNSAndReconnect(connectionString string, suppressRegister bool) bool {
	host, _, err := net.SplitHostPort(connectionString)
	if err != nil {
		Log.Error("Failed to parse connection string for DNS check:", err)
		return false
	}

	// Check if DNS has changed WITHOUT updating cached IPs yet
	// We only update cached IPs if we actually perform the reconnection
	changed, newIPs, err := checkDNSChanged(context.Background(), host, dnsResolver)
	if err != nil || !changed {
		return false
	}

	Log.Info("MDCB DNS resolution changed, reconnecting as self-healing mechanism...")

	// Check if reconnection is already in progress (from proactive monitor or another reactive check)
	// Use the same atomic flag as the DNS monitor to prevent concurrent reconnections
	if !reconnectionInProgress.CompareAndSwap(false, true) {
		Log.Warning("Reactive DNS check: reconnection already in progress, skipping duplicate reconnection")
		// Don't update cached IPs since we're not reconnecting
		return false
	}

	// Update cached IPs now that we're going to reconnect
	updateCachedIPs(newIPs)

	// Perform reconnection synchronously (we're already in error handling path)
	defer reconnectionInProgress.Store(false)

	safeReconnectRPCClient(suppressRegister)
	return true
}

// checkAndHandleDNSChange checks if DNS has changed and handles reconnection if needed.
// Returns true if DNS changed and reconnection was attempted, false otherwise.
// Also returns a boolean indicating whether the function should retry the RPC call.
func checkAndHandleDNSChange(connectionString string, suppressRegister bool) (dnsChanged bool, shouldRetry bool) {

	// Skip if we've already checked DNS after an error, or we're in emergency mode
	if values.GetDNSCheckedAfterError() || values.GetEmergencyMode() {
		Log.Debug("Skipping DNS check - already checked or in emergency mode")
		return false, false
	}

	// Mark that we've checked DNS
	values.SetDNSCheckedAfterError(true)
	Log.Info("RPC error detected, checking DNS as self-healing mechanism...")

	// Check if DNS has changed and reconnect if needed
	if changed := checkDNSAndReconnect(connectionString, suppressRegister); changed {
		return true, true // DNS changed, should retry
	}

	// DNS hasn't changed
	Log.Warning("MDCB connection failed. DNS unchanged - check MDCB service and network.")
	return false, false // DNS unchanged, should not retry
}

func defaultSafeReconnectRPCClient(suppressRegister bool) {
	// Stop DNS monitor before reconnecting
	StopDNSMonitor()

	// Stop existing client
	if clientSingleton != nil {
		oldClient := clientSingleton
		clientSingleton = nil // Clear reference first
		oldClient.Stop()      // Then stop the old client
	}

	// Reinitialize client
	Log.Info("Reinitializing RPC client after DNS change...")
	initializeClient()

	// Reinitialize function client
	if dispatcher != nil {
		funcClientSingleton = dispatcher.NewFuncClient(clientSingleton)
	}

	// Relogin
	handleLogin()
	if !suppressRegister {
		register()
	}

	// Restart DNS monitor if it was enabled
	config := values.Config()
	if !suppressRegister && config.DNSMonitorEnabled {
		StartDNSMonitor(config.DNSMonitorEnabled, config.DNSMonitorInterval, config.ConnectionString)
	}
}
