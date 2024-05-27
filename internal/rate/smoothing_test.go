package rate

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/event"
)

func TestSmoothing(t *testing.T) {
	tests := []struct {
		name              string
		session           *apidef.RateLimitSmoothing
		currentRate       int64
		maxAllowedRate    int64
		expectedResult    bool
		expectedError     error
		expectedAllowance int64
		expectedEvent     event.Event
	}{
		{
			name: "Smoothing disabled",
			session: &apidef.RateLimitSmoothing{
				Enabled: false,
				Delay:   1,
			},
			currentRate:    50,
			maxAllowedRate: 100,
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name: "Current rate below threshold",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Allowance: 100,
				Step:      10,
				Trigger:   0.8,
				Threshold: 80,
				Delay:     1,
			},
			currentRate:       70, // Below the threshold
			maxAllowedRate:    150,
			expectedResult:    true,
			expectedError:     nil,
			expectedAllowance: 90, // Allowance decreased by Rate
			expectedEvent:     event.RateLimitSmoothingDown,
		},
		{
			name: "Allowance increases",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Allowance: 400,
				Step:      100,
				Trigger:   0.8,
				Threshold: 50,
				Delay:     1,
			},
			currentRate:       350, // currentRate > allowance - (trigger * session.Rate) => 350 > 400 - (0.8 * 100)
			maxAllowedRate:    500,
			expectedResult:    true,
			expectedError:     nil,
			expectedAllowance: 500,
			expectedEvent:     event.RateLimitSmoothingUp,
		},
		{
			name: "Allowance decreases",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Allowance: 100,
				Step:      10,
				Trigger:   0.8,
				Threshold: 50,
				Delay:     1,
			},
			currentRate:       40, // currentRate <= (newAllowance - trigger * rate) => 40 <= (90 - 0.8 * 10)
			maxAllowedRate:    150,
			expectedResult:    true,
			expectedError:     nil,
			expectedAllowance: 90,
			expectedEvent:     event.RateLimitSmoothingDown,
		},
		{
			name: "New allowance exceeds max allowed rate",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Allowance: 400,
				Step:      100,
				Trigger:   0.8,
				Threshold: 50,
				Delay:     1,
			},
			currentRate:       350, // currentRate > allowance - (trigger * session.Rate) => 350 > 400 - (0.8 * 100)
			maxAllowedRate:    450,
			expectedResult:    true,
			expectedError:     nil,
			expectedAllowance: 450, // New allowance clamped to maxAllowedRate
			expectedEvent:     event.RateLimitSmoothingUp,
		},
		{
			name: "New allowance below threshold",
			session: &apidef.RateLimitSmoothing{
				Enabled:   true,
				Allowance: 70,
				Step:      20,
				Trigger:   0.8,
				Threshold: 60,
				Delay:     1,
			},
			currentRate:       10,
			maxAllowedRate:    150,
			expectedResult:    true,
			expectedError:     nil,
			expectedAllowance: 60, // Allowance decreased by Rate
			expectedEvent:     event.RateLimitSmoothingDown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP request with context
			ctx := context.Background()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/foo", nil)

			// Ensure the AllowanceNextUpdateAt is reset to allow changes
			tt.session.AllowanceNextUpdateAt = time.Time{}

			// Assert that the session can set an allowance
			assert.True(t, tt.session.CanSetAllowance())

			result, err := Smoothing(req, tt.session, "test-key", tt.currentRate, tt.maxAllowedRate)

			assert.Equal(t, tt.expectedResult, result)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
			if tt.expectedResult {
				assert.Equal(t, tt.expectedAllowance, tt.session.Allowance)
				// Check for the expected event
				events := event.Get(req.Context())
				assert.Len(t, events, 1)
				assert.Contains(t, events, tt.expectedEvent)
			} else {
				events := event.Get(req.Context())
				assert.Len(t, events, 0)
			}
		})
	}
}
