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

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Check for specific network-related error patterns
	return strings.Contains(errStr, "unexpected response type: <nil>. Expected *dispatcherResponse") ||
		strings.Contains(errStr, "Cannot obtain response during timeout") ||
		strings.Contains(errStr, "rpc is either down or was not configured") ||
		strings.Contains(errStr, "Cannot decode response")
}
