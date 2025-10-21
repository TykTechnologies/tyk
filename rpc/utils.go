package rpc

import "strings"

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

// isDNSError checks if an error is a DNS-related error that might be resolved by DNS change
func isDNSError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Only check for actual DNS-related errors that might be resolved by DNS change
	// "no such host" - DNS resolution failed for hostname
	// "lookup" + "timeout" - DNS lookup timeout
	return strings.Contains(errStr, "no such host") ||
		(strings.Contains(errStr, "lookup") && strings.Contains(errStr, "timeout"))
}
