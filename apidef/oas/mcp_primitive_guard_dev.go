//go:build !release

package oas

// ensureNotBypassingOverride validates that the caller passed *MCPPrimitive and not *Operation.
// This development helper catches accidental usage of &primitive.Operation which would bypass overrides.
// Only active in non-release builds to catch bugs during development and testing.
func ensureNotBypassingOverride(v interface{}) {
	if _, ok := v.(*Operation); ok {
		panic("BUG: Extracting Operation directly instead of MCPPrimitive - bypasses overrides!")
	}
}
