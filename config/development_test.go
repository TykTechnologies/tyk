//go:build dev
// +build dev

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-030, SYS-REQ-118, SW-REQ-105
// SW-REQ-105:nominal:nominal
// SW-REQ-105:boundary:nominal
// MCDC SYS-REQ-118: development_configuration_operation_requested=F, development_configuration_result_determined=F => TRUE
// MCDC SYS-REQ-118: development_configuration_operation_requested=T, development_configuration_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-118: development_configuration_operation_requested=T, development_configuration_result_determined=F => FALSE -- violation row is the negation of the local development configuration helper guarantee; these tests assert requested build-tag configuration operations return deterministic storage selection for dev and release builds [category: defensive] [reviewed: agent:codex]
func TestGetRateLimiterStorageDevBuild(t *testing.T) {
	customStorage := &StorageOptionsConf{Type: "local"}

	tests := []struct {
		name        string
		config      Config
		wantDefault bool
	}{
		{
			name: "disabled uses default storage",
			config: Config{
				Storage: StorageOptionsConf{Type: "redis"},
				DevelopmentConfig: DevelopmentConfig{
					EnableRateLimiterStorage: false,
					RateLimiterStorage:       customStorage,
				},
			},
			wantDefault: true,
		},
		{
			name: "enabled without rate limiter storage uses default storage",
			config: Config{
				Storage: StorageOptionsConf{Type: "redis"},
				DevelopmentConfig: DevelopmentConfig{
					EnableRateLimiterStorage: true,
				},
			},
			wantDefault: true,
		},
		{
			name: "enabled with rate limiter storage uses custom storage",
			config: Config{
				Storage: StorageOptionsConf{Type: "redis"},
				DevelopmentConfig: DevelopmentConfig{
					EnableRateLimiterStorage: true,
					RateLimiterStorage:       customStorage,
				},
			},
			wantDefault: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := tt.config

			got := conf.GetRateLimiterStorage()
			if tt.wantDefault {
				assert.Same(t, &conf.Storage, got)
				return
			}

			assert.Same(t, conf.RateLimiterStorage, got)
		})
	}
}
