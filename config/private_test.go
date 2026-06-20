package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-031, SYS-REQ-119, SW-REQ-106
// SW-REQ-106:nominal:nominal
// SW-REQ-106:boundary:nominal
// MCDC SYS-REQ-119: private_configuration_operation_requested=F, private_configuration_result_determined=F => TRUE
// MCDC SYS-REQ-119: private_configuration_operation_requested=T, private_configuration_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-119: private_configuration_operation_requested=T, private_configuration_result_determined=F => FALSE -- violation row is the negation of the local private configuration helper guarantee; these tests assert requested purge interval selection returns either the default duration or the configured duration [category: defensive] [reviewed: agent:codex]
func TestPrivate_GetOAuthTokensPurgeInterval(t *testing.T) {
	tests := []struct {
		name string
		conf Private
		want time.Duration
	}{
		{
			name: "default value",
			conf: Private{},
			want: time.Hour,
		},
		{
			name: "custom value",
			conf: Private{OAuthTokensPurgeInterval: 5},
			want: time.Second * 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.conf.GetOAuthTokensPurgeInterval())
		})
	}
}
