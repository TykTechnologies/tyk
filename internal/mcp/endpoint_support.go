package mcp

import "slices"

// ProtocolSupport is the internal contract shared by ingress and discovery.
type ProtocolSupport interface{ SupportedProtocolVersions() []string }

// ServedProtocolVersions lists native proxy support in deterministic order.
func ServedProtocolVersions() []string {
	return append([]string{ModernProtocolVersion}, LegacyProtocolVersions()...)
}

// LegacyProtocolVersions lists versions supported by the baseline synthetic runtime.
func LegacyProtocolVersions() []string {
	return []string{"2025-11-25", "2025-06-18", LegacyFallbackProtocolVersion}
}

func IsServedProtocolVersion(version string) bool {
	return slices.Contains(ServedProtocolVersions(), version)
}
