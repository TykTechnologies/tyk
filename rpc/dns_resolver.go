package rpc

import (
	"net"
	"sync"
)

var (
	// for dns monitoring
	lastResolvedIPs []string
	dnsRefreshMutex sync.RWMutex

	// global resolver to be replaced in tests
	dnsResolver DNSResolver = &DefaultDNSResolver{}
)

// DNSResolver provides methods for DNS resolution
type DNSResolver interface {
	LookupIP(host string) ([]net.IP, error)
}

// DefaultDNSResolver implements DNSResolver using the standard library
type DefaultDNSResolver struct{}

func (r *DefaultDNSResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// SetDNSResolver function to set the resolver (for testing)
func SetDNSResolver(resolver DNSResolver) {
	dnsResolver = resolver
}

// updateResolvedIPs checks if DNS resolution has changed using the provided resolver
func updateResolvedIPs(host string, resolver DNSResolver) bool {
	ips, err := resolver.LookupIP(host)
	if err != nil {
		Log.Error("Failed to resolve host during DNS refresh:", err)
		return false
	}

	// Extract IPv4 addresses
	newIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			newIPs = append(newIPs, ipv4.String())
		}
	}

	dnsRefreshMutex.Lock()
	defer dnsRefreshMutex.Unlock()

	// Check if IPs have changed
	changed := !equalStringSlices(lastResolvedIPs, newIPs)
	if changed {
		Log.Debug("DNS resolution changed from", lastResolvedIPs, "to", newIPs)
		lastResolvedIPs = newIPs
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

	// Check if DNS has changed
	if changed := updateResolvedIPs(host, dnsResolver); changed {
		Log.Info("MDCB DNS resolution changed, reconnecting as self-healing mechanism...")
		safeReconnectRPCClient(suppressRegister)
		return true
	}
	return false
}

// checkAndHandleDNSChange checks if DNS has changed and handles reconnection if needed.
// Returns true if DNS changed and reconnection was attempted, false otherwise.
// Also returns a boolean indicating whether the function should retry the RPC call.
func checkAndHandleDNSChange(connectionString string, suppressRegister bool) (dnsChanged bool, shouldRetry bool) {
	// Skip if we've already checked DNS after an error, or we're in emergency mode
	if values.GetDNSCheckedAfterError() || values.GetEmergencyMode() {
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

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[string]struct{}, len(a))
	for _, val := range a {
		mapA[val] = struct{}{}
	}

	for _, val := range b {
		if _, exists := mapA[val]; !exists {
			return false
		}
	}

	return true
}
