//go:build release

package oas

// ensureNotBypassingOverride is a no-op in release builds.
// In development builds, this function validates correct usage of MCPPrimitive.
func ensureNotBypassingOverride(v interface{}) {
	// No-op in production to avoid panic-based denial of service
}
