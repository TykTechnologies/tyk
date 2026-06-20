package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-032, SYS-REQ-120, SW-REQ-107
// STK-REQ-032:STK-REQ-032-AC-01:acceptance
// STK-REQ-032:STK-REQ-032-AC-02:acceptance
// STK-REQ-032:STK-REQ-032-AC-03:acceptance
// SW-REQ-107:nominal:nominal
// SW-REQ-107:boundary:nominal
// MCDC SYS-REQ-120: rate_limit_description_requested=F, rate_limit_description_determined=F => TRUE
// MCDC SYS-REQ-120: rate_limit_description_requested=T, rate_limit_description_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-120: rate_limit_description_requested=T, rate_limit_description_determined=F => FALSE -- violation row is the negation of the local rate-limit description helper guarantee; these tests assert requested string selection returns the configured limiter description for every supported local branch [category: defensive] [reviewed: agent:codex]
func TestRateLimitString(t *testing.T) {
	tests := []struct {
		name string
		conf RateLimit
		want string
	}{
		{
			name: "default distributed redis limiter uses transactions",
			conf: RateLimit{},
			want: "DRL with Redis Rate Limiter enabled (using transactions)",
		},
		{
			name: "default distributed redis limiter can use pipeline",
			conf: RateLimit{
				EnableNonTransactionalRateLimiter: true,
			},
			want: "DRL with Redis Rate Limiter enabled (using pipeline)",
		},
		{
			name: "fixed window takes precedence over all other limiter flags",
			conf: RateLimit{
				EnableFixedWindowRateLimiter:      true,
				EnableRedisRollingLimiter:         true,
				EnableSentinelRateLimiter:         true,
				DRLEnableSentinelRateLimiter:      true,
				EnableRateLimitSmoothing:          true,
				EnableNonTransactionalRateLimiter: true,
			},
			want: "Fixed Window Rate Limiter enabled",
		},
		{
			name: "redis rolling limiter reports transactions and smoothing",
			conf: RateLimit{
				EnableRedisRollingLimiter: true,
				EnableRateLimitSmoothing:  true,
			},
			want: "Redis Rate Limiter enabled (using transactions, with smoothing)",
		},
		{
			name: "redis rolling limiter takes precedence over sentinel flags",
			conf: RateLimit{
				EnableRedisRollingLimiter:         true,
				EnableSentinelRateLimiter:         true,
				DRLEnableSentinelRateLimiter:      true,
				EnableNonTransactionalRateLimiter: true,
			},
			want: "Redis Rate Limiter enabled (using pipeline)",
		},
		{
			name: "sentinel limiter reports transactions and smoothing",
			conf: RateLimit{
				EnableSentinelRateLimiter: true,
				EnableRateLimitSmoothing:  true,
			},
			want: "Redis Sentinel Rate Limiter enabled (using transactions, with smoothing)",
		},
		{
			name: "distributed sentinel fallback reports pipeline and smoothing",
			conf: RateLimit{
				DRLEnableSentinelRateLimiter:      true,
				EnableRateLimitSmoothing:          true,
				EnableNonTransactionalRateLimiter: true,
			},
			want: "DRL with Redis Sentinel Rate Limiter enabled (using pipeline, with smoothing)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.conf.String())
		})
	}
}
