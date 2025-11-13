package rate

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/rate/mock"
)

func TestNewSmoothing(t *testing.T) {
	val := NewSmoothing(nil)
	assert.NotNil(t, val)

	assert.NotEmpty(t, val.String())
}

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

func TestSmoothing_Do(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)

	testCases := []struct {
		name           string
		session        *apidef.RateLimitSmoothing
		allowanceStore *mock.AllowanceStore
		key            string
		currentRate    int64
		maxAllowedRate int64
		expectedErr    error
	}{
		{
			name: "valid session with new allowance",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Threshold: 10,
				Trigger:   0.5,
				Step:      1,
				Delay:     100,
			},
			allowanceStore: &mock.AllowanceStore{
				Allowance: &Allowance{},
			},
			key:            "testKey1",
			currentRate:    5,
			maxAllowedRate: 20,
			expectedErr:    nil,
		},
		{
			name: "invalid session",
			session: &apidef.RateLimitSmoothing{
				Enabled:   false,
				Threshold: 10,
				Trigger:   0.5,
				Step:      1,
				Delay:     100,
			},
			allowanceStore: &mock.AllowanceStore{},
			key:            "testKey2",
			currentRate:    5,
			maxAllowedRate: 20,
			expectedErr:    errors.New("smoothing invalid: rate limit smoothing disabled"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Smoothing{allowanceStore: tc.allowanceStore}

			_, err := d.Do(req, tc.session, tc.key, tc.currentRate, tc.maxAllowedRate)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
