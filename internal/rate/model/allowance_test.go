package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SYS-REQ-103:malformed_input:nominal
// SYS-REQ-103:malformed_input:negative
// SW-REQ-006:nominal:nominal
// SW-REQ-006:malformed_input:nominal
// SW-REQ-006:malformed_input:negative
// MCDC SYS-REQ-103: rate_limit_allowance_operation_requested=T, rate_limit_allowance_state_result_returned=T => TRUE
// MCDC SW-REQ-006: rate_limit_allowance_operation_requested=T, rate_limit_allowance_state_result_returned=T => TRUE
func TestNewAllowance(t *testing.T) {
	t.Run("NewAllowance", func(t *testing.T) {
		allowance := NewAllowance(0)
		assert.NotNil(t, allowance)
		assert.Equal(t, int64(0), allowance.Delay)
	})

	t.Run("Valid input", func(t *testing.T) {
		now := time.Now().Format(time.RFC3339Nano)
		input := map[string]string{
			"delay":        "10",
			"current":      "100",
			"nextUpdateAt": now,
		}
		allowance := NewAllowanceFromMap(input)
		assert.Equal(t, int64(10), allowance.Delay)
		assert.Equal(t, int64(100), allowance.Current)
		expectedTime, err := time.Parse(time.RFC3339Nano, now)
		assert.NoError(t, err)
		assert.Equal(t, expectedTime, allowance.NextUpdateAt)
	})

	t.Run("Invalid input with invalid values", func(t *testing.T) {
		input := map[string]string{
			"delay":        "invalid",
			"current":      "invalid",
			"nextUpdateAt": "invalid",
		}
		allowance := NewAllowanceFromMap(input)
		assert.Equal(t, int64(0), allowance.Delay)
		assert.Equal(t, int64(0), allowance.Current)
		assert.True(t, allowance.NextUpdateAt.IsZero())
	})

	t.Run("Invalid input with no values", func(t *testing.T) {
		input := map[string]string{}
		allowance := NewAllowanceFromMap(input)
		assert.Equal(t, int64(0), allowance.Delay)
		assert.Equal(t, int64(0), allowance.Current)
		assert.True(t, allowance.NextUpdateAt.IsZero())
	})

}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:boundary:nominal
// SW-REQ-006:boundary:nominal
func TestAllowance_Valid(t *testing.T) {
	t.Run("Valid allowance", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   10,
			Current: 100,
		}
		assert.True(t, allowance.Valid())
	})

	t.Run("Invalid allowance with zero delay", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   0,
			Current: 100,
		}
		assert.False(t, allowance.Valid())
	})

	t.Run("Invalid allowance with negative delay", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   -1,
			Current: 100,
		}
		assert.False(t, allowance.Valid())
	})
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:error_handling:nominal
// SYS-REQ-103:error_handling:negative
// SW-REQ-006:error_handling:nominal
// SW-REQ-006:error_handling:negative
// MCDC SYS-REQ-103: rate_limit_allowance_operation_requested=T, rate_limit_allowance_state_result_returned=F => FALSE
// MCDC SW-REQ-006: rate_limit_allowance_operation_requested=T, rate_limit_allowance_state_result_returned=F => FALSE
func TestAllowance_Err(t *testing.T) {
	t.Run("Valid allowance", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   10,
			Current: 100,
		}
		assert.NoError(t, allowance.Err())
	})

	t.Run("Invalid allowance with zero delay", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   0,
			Current: 100,
		}
		err := allowance.Err()
		assert.Error(t, err)
	})

	t.Run("Invalid allowance with negative delay", func(t *testing.T) {
		allowance := &Allowance{
			Delay:   -1,
			Current: 100,
		}
		err := allowance.Err()
		assert.Error(t, err)
	})
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nil_safety:nominal
// SYS-REQ-103:nil_safety:negative
// SW-REQ-006:nil_safety:nominal
// SW-REQ-006:nil_safety:negative
func TestAllowance_Reset(t *testing.T) {
	var a *Allowance
	assert.NotPanics(t, func() {
		a.Reset()
	})
	assert.Nil(t, a)

	a = &Allowance{
		Delay:        10,
		Current:      100,
		NextUpdateAt: time.Now(),
	}
	a.Reset()

	assert.Equal(t, int64(0), a.Current)
	assert.True(t, a.NextUpdateAt.IsZero())
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SW-REQ-006:nominal:nominal
func TestAllowance_Map(t *testing.T) {
	nextUpdateAt := time.Date(2026, time.June, 19, 12, 34, 56, 987654321, time.UTC)
	a := &Allowance{
		Delay:        10,
		Current:      42,
		NextUpdateAt: nextUpdateAt,
	}

	assert.Equal(t, map[string]any{
		"delay":        "10",
		"current":      "42",
		"nextUpdateAt": nextUpdateAt.Format(time.RFC3339Nano),
	}, a.Map())
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SW-REQ-006:nominal:nominal
func TestAllowance_GetDelay(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	expectedDelay := 10 * time.Second
	assert.Equal(t, expectedDelay, a.GetDelay())
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SW-REQ-006:nominal:nominal
func TestAllowance_Get(t *testing.T) {
	a := &Allowance{
		Current: 100,
	}
	assert.Equal(t, int64(100), a.Get())
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SW-REQ-006:nominal:nominal
func TestAllowance_Set(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	a.Set(200)
	assert.Equal(t, int64(200), a.Current)
	assert.WithinDuration(t, time.Now().Add(10*time.Second), a.NextUpdateAt, time.Second)
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SW-REQ-006:nominal:nominal
func TestAllowance_Touch(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	a.Touch()
	assert.WithinDuration(t, time.Now().Add(10*time.Second), a.NextUpdateAt, time.Second)
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:boundary:nominal
// SW-REQ-006:boundary:nominal
func TestAllowance_Expired(t *testing.T) {
	a := &Allowance{
		NextUpdateAt: time.Now().Add(-time.Minute),
	}
	assert.True(t, a.Expired())

	a.NextUpdateAt = time.Now().Add(time.Minute)
	assert.False(t, a.Expired())
}

// Verifies: SYS-REQ-103, SW-REQ-006
// SYS-REQ-103:nominal:nominal
// SYS-REQ-103:boundary:nominal
// SW-REQ-006:nominal:nominal
// SW-REQ-006:boundary:nominal
func TestAllowance_StateAccessUpdateTimingAndExpiry(t *testing.T) {
	a := &Allowance{
		Delay:        2,
		Current:      7,
		NextUpdateAt: time.Now().Add(-time.Second),
	}

	assert.Equal(t, 2*time.Second, a.GetDelay())
	assert.Equal(t, int64(7), a.Get())
	assert.True(t, a.Expired())

	a.Set(11)
	assert.Equal(t, int64(11), a.Get())
	assert.WithinDuration(t, time.Now().Add(2*time.Second), a.NextUpdateAt, time.Second)
	assert.False(t, a.Expired())

	a.Touch()
	assert.WithinDuration(t, time.Now().Add(2*time.Second), a.NextUpdateAt, time.Second)
}
