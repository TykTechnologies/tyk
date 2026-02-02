// Package agentprotocol provides utilities for agent protocol handling (MCP, A2A, etc.).
package agentprotocol

import (
	"strings"
	"sync"
)

var (
	vemPrefixes []string
	mu          sync.RWMutex
)

// RegisterVEMPrefix registers a VEM path prefix for a protocol.
// This should be called during package initialization.
func RegisterVEMPrefix(prefix string) {
	mu.Lock()
	defer mu.Unlock()
	vemPrefixes = append(vemPrefixes, prefix)
}

// IsProtocolVEMPath returns true if the path is a protocol-specific VEM path.
// These paths are internal-only and should return 404 when accessed directly.
func IsProtocolVEMPath(path string) bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, prefix := range vemPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
