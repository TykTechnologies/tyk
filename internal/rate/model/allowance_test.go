package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewAllowance(t *testing.T) {
	t.Run("NewAllowance", func(t *testing.T) {
		allowance := NewAllowance(0)
		assert.NotNil(t, allowance)
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

func TestAllowance_Reset(t *testing.T) {
	var a *Allowance
	a.Reset()
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

func TestAllowance_GetDelay(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	expectedDelay := 10 * time.Second
	assert.Equal(t, expectedDelay, a.GetDelay())
}

func TestAllowance_Get(t *testing.T) {
	a := &Allowance{
		Current: 100,
	}
	assert.Equal(t, int64(100), a.Get())
}

func TestAllowance_Set(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	a.Set(200)
	assert.Equal(t, int64(200), a.Current)
	assert.False(t, a.NextUpdateAt.IsZero())
}

func TestAllowance_Touch(t *testing.T) {
	a := &Allowance{
		Delay: 10,
	}
	a.Touch()
	assert.WithinDuration(t, time.Now().Add(10*time.Second), a.NextUpdateAt, time.Second)
}

func TestAllowance_Expired(t *testing.T) {
	a := &Allowance{
		NextUpdateAt: time.Now().Add(-time.Minute),
	}
	assert.True(t, a.Expired())

	a.NextUpdateAt = time.Now().Add(time.Minute)
	assert.False(t, a.Expired())
}
