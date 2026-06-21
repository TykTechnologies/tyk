package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: STK-REQ-070, SYS-REQ-158, SW-REQ-145
// STK-REQ-070:STK-REQ-070-AC-01:acceptance
// SW-REQ-145:nominal:nominal
// SW-REQ-145:boundary:nominal
// SW-REQ-145:boundary:boundary
// SW-REQ-145:determinism:nominal
// SYS-REQ-158:determinism:nominal
// MCDC SYS-REQ-158: user_limit_model_operation_terminal=T => TRUE
//
//mcdc:ignore SYS-REQ-158: user_limit_model_operation_terminal=F => FALSE -- the onboarded user limit model operations are synchronous local helpers that either derive an APILimit value, compute a duration or disabled zero duration, report empty/configured state, clone APILimit data, report policy predicates, or report partition enablement before returning; a non-terminal local result is not a reachable runtime state for these APIs [category: defensive] [reviewed: human:buger]
func TestUserLimitModelHelpers(t *testing.T) {
	smoothing := &apidef.RateLimitSmoothing{Enabled: true, Threshold: 10, Trigger: 20, Step: 2, Delay: 1}

	t.Run("policy APILimit derives limit fields", func(t *testing.T) {
		policy := &Policy{
			Rate:               50,
			Per:                10,
			QuotaMax:           1000,
			QuotaRenewalRate:   60,
			ThrottleInterval:   1.5,
			ThrottleRetryLimit: 3,
			MaxQueryDepth:      7,
			Smoothing:          smoothing,
		}

		assert.Equal(t, APILimit{
			QuotaMax:           1000,
			QuotaRenewalRate:   60,
			ThrottleInterval:   1.5,
			ThrottleRetryLimit: 3,
			MaxQueryDepth:      7,
			RateLimit: RateLimit{
				Rate:      50,
				Per:       10,
				Smoothing: smoothing,
			},
		}, policy.APILimit())
	})

	t.Run("session APILimit derives limit fields", func(t *testing.T) {
		session := &SessionState{
			Rate:               25,
			Per:                5,
			QuotaMax:           200,
			QuotaRenews:        300,
			QuotaRemaining:     150,
			QuotaRenewalRate:   30,
			ThrottleInterval:   2,
			ThrottleRetryLimit: 4,
			MaxQueryDepth:      9,
			Smoothing:          smoothing,
		}

		assert.Equal(t, APILimit{
			RateLimit: RateLimit{
				Rate:      25,
				Per:       5,
				Smoothing: smoothing,
			},
			ThrottleInterval:   2,
			ThrottleRetryLimit: 4,
			MaxQueryDepth:      9,
			QuotaMax:           200,
			QuotaRenews:        300,
			QuotaRenewalRate:   30,
		}, session.APILimit())
	})

	t.Run("rate limit zero and duration", func(t *testing.T) {
		tests := []struct {
			name     string
			limit    RateLimit
			wantZero bool
			want     time.Duration
		}{
			{name: "zero", wantZero: true},
			{name: "smoothing only is non-zero", limit: RateLimit{Smoothing: smoothing}, wantZero: false},
			{name: "disabled by rate", limit: RateLimit{Per: 2}, want: 0},
			{name: "disabled by period", limit: RateLimit{Rate: 2}, want: 0},
			{name: "configured", limit: RateLimit{Rate: 4, Per: 2}, want: 500 * time.Millisecond},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.wantZero, tt.limit.IsZero())
				assert.Equal(t, tt.want, tt.limit.Duration())
			})
		}
	})

	t.Run("APILimit predicates", func(t *testing.T) {
		tests := []struct {
			name         string
			limit        APILimit
			wantEmpty    bool
			wantAllZero  bool
			wantQuota    bool
			wantThrottle bool
		}{
			{name: "zero", wantEmpty: true, wantAllZero: true},
			{name: "rate configured", limit: APILimit{RateLimit: RateLimit{Rate: 1, Per: 1}}, wantAllZero: false},
			{name: "quota configured", limit: APILimit{QuotaMax: 1}, wantQuota: true},
			{name: "throttle requires both fields", limit: APILimit{ThrottleInterval: 1}, wantAllZero: true},
			{name: "throttle configured", limit: APILimit{ThrottleInterval: 1, ThrottleRetryLimit: 1}, wantAllZero: true, wantThrottle: true},
			{name: "set by is non-empty", limit: APILimit{SetBy: "policy"}, wantAllZero: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.wantEmpty, tt.limit.IsEmpty())
				assert.Equal(t, tt.wantEmpty, tt.limit.IsZero())
				assert.Equal(t, tt.wantAllZero, tt.limit.IsAllZero())
				assert.Equal(t, tt.wantQuota, tt.limit.HasQuotaConfigured())
				assert.Equal(t, tt.wantThrottle, tt.limit.HasThrottleWindow())
			})
		}
	})

	t.Run("APILimit clone copies smoothing by value", func(t *testing.T) {
		original := APILimit{
			RateLimit:          RateLimit{Rate: 10, Per: 1, Smoothing: smoothing},
			ThrottleInterval:   1,
			ThrottleRetryLimit: 2,
			MaxQueryDepth:      3,
			QuotaMax:           4,
			QuotaRenews:        5,
			QuotaRemaining:     6,
			QuotaRenewalRate:   7,
			SetBy:              "policy",
		}

		clone := original.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, original, *clone)
		require.NotSame(t, original.Smoothing, clone.Smoothing)

		clone.Smoothing.Enabled = false
		assert.True(t, original.Smoothing.Enabled)
	})

	t.Run("policy predicates", func(t *testing.T) {
		tests := []struct {
			name           string
			policy         Policy
			activeQuota    bool
			nonNegQuota    bool
			configRate     bool
			configThrottle bool
		}{
			{name: "active quota", policy: Policy{QuotaMax: 1, Active: true}, activeQuota: true, nonNegQuota: true},
			{name: "inactive blocks active quota", policy: Policy{QuotaMax: 1, Active: true, IsInactive: true}, nonNegQuota: true},
			{name: "negative quota", policy: Policy{QuotaMax: -1, Active: true}},
			{name: "rate requires rate and per", policy: Policy{Rate: 1}, nonNegQuota: true},
			{name: "configured rate", policy: Policy{Rate: 1, Per: 2}, nonNegQuota: true, configRate: true},
			{name: "configured throttle", policy: Policy{ThrottleRetryLimit: 1}, nonNegQuota: true, configThrottle: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.activeQuota, tt.policy.IsActiveQuotaConfigured())
				assert.Equal(t, tt.nonNegQuota, tt.policy.HasNonNegativeQuota())
				assert.Equal(t, tt.configRate, tt.policy.HasConfiguredRate())
				assert.Equal(t, tt.configThrottle, tt.policy.HasConfiguredThrottle())
			})
		}
	})

	t.Run("policy partition enablement", func(t *testing.T) {
		tests := []struct {
			name string
			in   PolicyPartitions
			want bool
		}{
			{name: "zero"},
			{name: "quota", in: PolicyPartitions{Quota: true}, want: true},
			{name: "rate limit", in: PolicyPartitions{RateLimit: true}, want: true},
			{name: "acl", in: PolicyPartitions{Acl: true}, want: true},
			{name: "complexity", in: PolicyPartitions{Complexity: true}, want: true},
			{name: "per api alone does not enable partitioning", in: PolicyPartitions{PerAPI: true}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, tt.in.Enabled())
			})
		}
	})
}
