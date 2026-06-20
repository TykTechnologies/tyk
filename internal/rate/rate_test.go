package rate

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	ratemodel "github.com/TykTechnologies/tyk/internal/rate/model"
	"github.com/TykTechnologies/tyk/user"
)

// Verifies: SW-REQ-010
// SW-REQ-010:nominal:nominal
// SW-REQ-010:boundary:nominal
// SW-REQ-010:boundary:boundary
func TestPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "joins non-empty fragments",
			parts:    []string{"a", "b", "c"},
			expected: "a-b-c",
		},
		{
			name:     "skips empty fragments",
			parts:    []string{"a", "b", "", "c"},
			expected: "a-b-c",
		},
		{
			name:     "trims dash separators",
			parts:    []string{"-rate-limit-", "--session--", "-allowance"},
			expected: "rate-limit-session-allowance",
		},
		{
			name:     "returns empty for empty or separator-only fragments",
			parts:    []string{"", "---", "--"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Prefix(tt.parts...))
		})
	}
}

// Verifies: SW-REQ-014
// SW-REQ-014:nominal:nominal
func TestRootAllowanceAliases(t *testing.T) {
	t.Parallel()

	var allowance *Allowance = NewAllowance(7)
	require.NotNil(t, allowance)
	assert.Equal(t, int64(7), allowance.Delay)

	decoded := NewAllowanceFromMap(map[string]string{
		"delay":        "11",
		"current":      "19",
		"nextUpdateAt": time.Now().Format(time.RFC3339Nano),
	})
	assert.Equal(t, int64(11), decoded.Delay)
	assert.Equal(t, int64(19), decoded.Current)

	var modelAllowance *ratemodel.Allowance = allowance
	assert.Same(t, modelAllowance, allowance)
}

// Verifies: SW-REQ-013
// SW-REQ-013:nominal:nominal
// SW-REQ-013:boundary:nominal
// SW-REQ-013:boundary:boundary
func TestStatsHelpers(t *testing.T) {
	t.Parallel()

	empty := NewEmptyStats()
	assert.Equal(t, time.Duration(0), empty.Reset)
	assert.Zero(t, empty.Limit)
	assert.Zero(t, empty.Remaining)
	assert.Zero(t, empty.Count)
	assert.False(t, empty.ShouldBlock())

	assert.False(t, Stats{Count: 10, Limit: 10}.ShouldBlock())
	assert.True(t, Stats{Count: 11, Limit: 10}.ShouldBlock())
}

// Verifies: SW-REQ-013
// SW-REQ-013:nominal:nominal
// SW-REQ-013:error_handling:nominal
// SW-REQ-013:error_handling:negative
func TestAnonChecker(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("check failed")
	tests := []struct {
		name        string
		stats       Stats
		blocked     bool
		err         error
		expectedErr error
	}{
		{
			name:    "delegates successful checker result",
			stats:   Stats{Count: 1, Limit: 2, Remaining: 1},
			blocked: false,
		},
		{
			name:        "preserves delegated checker error",
			stats:       Stats{Count: 3, Limit: 2, Remaining: 0},
			blocked:     true,
			err:         expectedErr,
			expectedErr: expectedErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := AnonChecker(func() (Stats, bool, error) {
				return tt.stats, tt.blocked, tt.err
			})

			stats, blocked, err := checker.Check()

			assert.Equal(t, tt.stats, stats)
			assert.Equal(t, tt.blocked, blocked)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

// Verifies: SW-REQ-015
// SW-REQ-015:nominal:nominal
// SW-REQ-015:boundary:nominal
// SW-REQ-015:boundary:boundary
func TestLimiterSelection(t *testing.T) {
	t.Parallel()

	name, ok := limiterKind(&config.Config{})
	assert.False(t, ok)
	assert.Empty(t, name)
	assert.Nil(t, Limiter(&config.Config{}, nil))

	cfg := &config.Config{}
	cfg.EnableFixedWindowRateLimiter = true

	name, ok = limiterKind(cfg)
	assert.True(t, ok)
	assert.Equal(t, LimitFixedWindow, name)
	assert.NotNil(t, Limiter(cfg, nil))
}

// Verifies: SW-REQ-015
// SW-REQ-015:nominal:nominal
// SW-REQ-015:boundary:nominal
// SW-REQ-015:boundary:boundary
func TestLimiterKey(t *testing.T) {
	t.Parallel()

	session := &user.SessionState{}
	session.SetKeyHash("cached-hash")

	assert.Equal(t, "rate-limit-api-cached-hash", LimiterKey(session, "api", "raw-key", false))
	assert.Equal(t, "rate-limit-api-raw-key", LimiterKey(session, "api", "raw-key", true))
	assert.Equal(t, "rate-limit-api-raw-key", LimiterKey(&user.SessionState{}, "api", "raw-key", false))
}
