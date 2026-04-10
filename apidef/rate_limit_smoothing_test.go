package apidef

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRateLimitSmoothing_Valid(t *testing.T) {
	t.Run("Valid case", func(t *testing.T) {
		r := &RateLimitSmoothing{
			Enabled:   true,
			Step:      10,
			Delay:     5,
			Threshold: 100,
			Trigger:   0.5,
		}
		assert.True(t, r.Valid(), "expected Valid() to return true for valid settings")
	})

	t.Run("Invalid case", func(t *testing.T) {
		r := &RateLimitSmoothing{
			Enabled:   true,
			Step:      -1,
			Delay:     5,
			Threshold: 100,
			Trigger:   0.5,
		}
		assert.False(t, r.Valid(), "expected Valid() to return false for invalid settings")
	})
}

func TestRateLimitSmoothing_Err(t *testing.T) {
	tests := []struct {
		name      string
		r         *RateLimitSmoothing
		expectErr bool
	}{
		{
			name: "Valid settings",
			r: &RateLimitSmoothing{
				Enabled:   true,
				Step:      10,
				Delay:     5,
				Threshold: 100,
				Trigger:   0.5,
			},
			expectErr: false,
		},
		{
			name: "Disabled smoothing",
			r: &RateLimitSmoothing{
				Enabled: false,
			},
			expectErr: true,
		},
		{
			name: "Invalid step",
			r: &RateLimitSmoothing{
				Enabled:   true,
				Step:      -1,
				Delay:     5,
				Threshold: 100,
				Trigger:   0.5,
			},
			expectErr: true,
		},
		{
			name: "Invalid delay",
			r: &RateLimitSmoothing{
				Enabled:   true,
				Step:      10,
				Delay:     -1,
				Threshold: 100,
				Trigger:   0.5,
			},
			expectErr: true,
		},
		{
			name: "Invalid threshold",
			r: &RateLimitSmoothing{
				Enabled:   true,
				Step:      10,
				Delay:     5,
				Threshold: -1,
				Trigger:   0.5,
			},
			expectErr: true,
		},
		{
			name: "Invalid trigger",
			r: &RateLimitSmoothing{
				Enabled:   true,
				Step:      10,
				Delay:     5,
				Threshold: 100,
				Trigger:   -0.1,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Err()
			if (err != nil) != tt.expectErr {
				t.Errorf("expected error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}
