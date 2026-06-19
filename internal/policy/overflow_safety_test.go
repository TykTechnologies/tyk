package policy

import (
	"testing"
)

// ---------------------------------------------------------------------------
// SYS-REQ-067: Overflow safety tests (in policy package for greaterThanInt64 access)
// ---------------------------------------------------------------------------

// Verifies: SYS-REQ-067
// SYS-REQ-067:overflow_safety:negative
// MCDC SYS-REQ-067: apply_requested=T, bounds_checked=F, overflow_safe=T => TRUE
func TestInternal_SYS_REQ_067_OverflowSafety(t *testing.T) {
	t.Run("near-max-int64 values", func(t *testing.T) {
		large := int64(9223372036854775807)
		small := int64(9223372036854775806)
		if !greaterThanInt64(large, small) {
			t.Error("expected greaterThanInt64(MaxInt64, MaxInt64-1) = true")
		}
		if greaterThanInt64(small, large) {
			t.Error("expected greaterThanInt64(MaxInt64-1, MaxInt64) = false")
		}
	})

	t.Run("sentinel -1 value", func(t *testing.T) {
		if !greaterThanInt64(-1, 9223372036854775807) {
			t.Error("expected greaterThanInt64(-1, MaxInt64) = true (sentinel unlimited)")
		}
		if greaterThanInt64(100, -1) {
			t.Error("expected greaterThanInt64(100, -1) = false")
		}
	})
}
