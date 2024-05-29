package rate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestNewSmoothing(t *testing.T) {
	val := NewSmoothing(nil)
	assert.NotNil(t, val)
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
