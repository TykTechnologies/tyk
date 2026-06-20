package rate

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/rate/mock"
)

// Verifies: SW-REQ-012
// SW-REQ-012:nominal:nominal
func TestNewSmoothing(t *testing.T) {
	val := NewSmoothing(nil)
	assert.NotNil(t, val)

	assert.NotEmpty(t, val.String())
}

// Verifies: SW-REQ-012
// SW-REQ-012:nominal:nominal
// SW-REQ-012:boundary:nominal
// SW-REQ-012:boundary:boundary
func TestIncreaseRateAllowance(t *testing.T) {
	session := &apidef.RateLimitSmoothing{
		Step:    10,
		Trigger: 0.5,
	}

	tests := []struct {
		name           string
		allowedRate    int64
		currentRate    int64
		maxAllowedRate int64
		expectedRate   int64
		expectedChange bool
	}{
		{
			name:           "Increase within limit",
			allowedRate:    50,
			currentRate:    45,
			maxAllowedRate: 100,
			expectedRate:   60,
			expectedChange: true,
		},
		{
			name:           "Increase exceeds max limit",
			allowedRate:    95,
			currentRate:    90,
			maxAllowedRate: 100,
			expectedRate:   100,
			expectedChange: true,
		},
		{
			name:           "No increase due to current rate",
			allowedRate:    50,
			currentRate:    30,
			maxAllowedRate: 100,
			expectedRate:   50,
			expectedChange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newRate, changed := increaseRateAllowance(session, tt.allowedRate, tt.currentRate, tt.maxAllowedRate)
			assert.Equal(t, tt.expectedRate, newRate)
			assert.Equal(t, tt.expectedChange, changed)
		})
	}
}

// Verifies: SW-REQ-012
// SW-REQ-012:nominal:nominal
// SW-REQ-012:boundary:nominal
// SW-REQ-012:boundary:boundary
func TestDecreaseRateAllowance(t *testing.T) {
	session := &apidef.RateLimitSmoothing{
		Step:    10,
		Trigger: 0.5,
	}

	tests := []struct {
		name           string
		allowedRate    int64
		currentRate    int64
		minAllowedRate int64
		expectedRate   int64
		expectedChange bool
	}{
		{
			name:           "Decrease within limit",
			allowedRate:    50,
			currentRate:    35,
			minAllowedRate: 10,
			expectedRate:   40,
			expectedChange: true,
		},
		{
			name:           "Decrease below min limit",
			allowedRate:    20,
			currentRate:    5,
			minAllowedRate: 15,
			expectedRate:   15,
			expectedChange: true,
		},
		{
			name:           "No decrease due to current rate",
			allowedRate:    50,
			currentRate:    50,
			minAllowedRate: 10,
			expectedRate:   50,
			expectedChange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newRate, changed := decreaseRateAllowance(session, tt.allowedRate, tt.currentRate, tt.minAllowedRate)
			assert.Equal(t, tt.expectedRate, newRate)
			assert.Equal(t, tt.expectedChange, changed)
		})
	}
}

// Verifies: SW-REQ-012
// SW-REQ-012:nominal:nominal
// SW-REQ-012:boundary:nominal
// SW-REQ-012:boundary:boundary
// SW-REQ-012:error_handling:nominal
// SW-REQ-012:error_handling:negative
func TestSmoothing_Do(t *testing.T) {
	ctx := context.Background()

	validSession := func() *apidef.RateLimitSmoothing {
		return &apidef.RateLimitSmoothing{
			Enabled:   true,
			Threshold: 10,
			Trigger:   0.5,
			Step:      10,
			Delay:     100,
		}
	}

	expiredAllowance := func(current int64) *Allowance {
		return &Allowance{
			Delay:        100,
			Current:      current,
			NextUpdateAt: time.Now().Add(-time.Second),
		}
	}

	freshAllowance := func(current int64) *Allowance {
		return &Allowance{
			Delay:        100,
			Current:      current,
			NextUpdateAt: time.Now().Add(time.Hour),
		}
	}

	t.Run("rejects invalid smoothing configuration", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, &apidef.RateLimitSmoothing{Enabled: false}, "key", 5, 20)

		require.Nil(t, allowance)
		require.EqualError(t, err, "smoothing invalid: rate limit smoothing disabled")
		assert.Zero(t, store.GetCalls)
	})

	t.Run("returns get error before locking", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{GetErr: errors.New("get failed")}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 5, 20)

		require.Nil(t, allowance)
		require.EqualError(t, err, "smoothing: getting allowance: get failed")
		assert.Zero(t, store.LockerCalls)
	})

	t.Run("creates initial allowance at threshold", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{Allowance: &Allowance{}}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 5, 20)

		require.NoError(t, err)
		require.NotNil(t, allowance)
		assert.Equal(t, int64(10), allowance.Current)
		assert.Equal(t, int64(100), allowance.Delay)
		assert.False(t, allowance.Expired())
		assert.Equal(t, 1, store.SetCalls)
		assert.Equal(t, 1, store.LockerCalls)
	})

	t.Run("returns previous allowance when initial set fails", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{Allowance: &Allowance{}, SetErr: errors.New("set failed")}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 5, 20)

		require.NotNil(t, allowance)
		assert.Equal(t, int64(10), allowance.Current)
		require.EqualError(t, err, "smoothing: can't set new allowance: set failed")
	})

	t.Run("skips update before delay expires", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		existing := freshAllowance(50)
		store := &mock.AllowanceStore{Allowance: existing}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		require.NoError(t, err)
		assert.Same(t, existing, allowance)
		assert.Zero(t, store.LockerCalls)
		assert.Zero(t, store.SetCalls)
	})

	t.Run("returns allowance and lock error", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		existing := expiredAllowance(50)
		store := &mock.AllowanceStore{Allowance: existing, LockErr: errors.New("lock failed")}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		assert.Same(t, existing, allowance)
		require.EqualError(t, err, "smoothing: getting lock, skipping update: lock failed")
		assert.Zero(t, store.SetCalls)
	})

	t.Run("returns reread error after locking", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{
			Allowances: []*Allowance{expiredAllowance(50)},
			GetErrs:    []error{nil, errors.New("reread failed")},
		}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		require.Nil(t, allowance)
		require.EqualError(t, err, "smoothing: getting allowance: reread failed")
		assert.Equal(t, 2, store.GetCalls)
		assert.Zero(t, store.SetCalls)
	})

	t.Run("skips update when reread allowance is fresh", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		fresh := freshAllowance(50)
		store := &mock.AllowanceStore{Allowances: []*Allowance{expiredAllowance(50), fresh}}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		require.NoError(t, err)
		assert.Same(t, fresh, allowance)
		assert.Zero(t, store.SetCalls)
	})

	t.Run("increases allowance and emits up event", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{Allowances: []*Allowance{expiredAllowance(50), expiredAllowance(50)}}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		require.NoError(t, err)
		require.NotNil(t, allowance)
		assert.Equal(t, int64(60), allowance.Current)
		assert.Equal(t, []event.Event{event.RateLimitSmoothingUp}, event.Get(req.Context()))
		assert.Equal(t, 1, store.SetCalls)
	})

	t.Run("returns previous allowance when increase set fails", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{
			Allowances: []*Allowance{expiredAllowance(50), expiredAllowance(50)},
			SetErr:     errors.New("set failed"),
		}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 45, 100)

		require.NotNil(t, allowance)
		assert.Equal(t, int64(50), allowance.Current)
		require.EqualError(t, err, "smoothing: can't set allowance increase: set failed")
		assert.Empty(t, event.Get(req.Context()))
	})

	t.Run("decreases allowance and emits down event", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{Allowances: []*Allowance{expiredAllowance(50), expiredAllowance(50)}}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 35, 100)

		require.NoError(t, err)
		require.NotNil(t, allowance)
		assert.Equal(t, int64(40), allowance.Current)
		assert.Equal(t, []event.Event{event.RateLimitSmoothingDown}, event.Get(req.Context()))
		assert.Equal(t, 1, store.SetCalls)
	})

	t.Run("returns previous allowance when decrease set fails", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		store := &mock.AllowanceStore{
			Allowances: []*Allowance{expiredAllowance(50), expiredAllowance(50)},
			SetErr:     errors.New("set failed"),
		}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 35, 100)

		require.NotNil(t, allowance)
		assert.Equal(t, int64(50), allowance.Current)
		require.EqualError(t, err, "smoothing: can't set allowance decrease: set failed")
		assert.Empty(t, event.Get(req.Context()))
	})

	t.Run("returns previous allowance when no smoothing change is needed", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
		previous := expiredAllowance(50)
		store := &mock.AllowanceStore{Allowances: []*Allowance{expiredAllowance(50), previous}}
		d := &Smoothing{allowanceStore: store}

		allowance, err := d.Do(req, validSession(), "key", 40, 100)

		require.NoError(t, err)
		assert.Same(t, previous, allowance)
		assert.Zero(t, store.SetCalls)
		assert.Empty(t, event.Get(req.Context()))
	})
}
