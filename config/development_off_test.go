//go:build !dev
// +build !dev

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-030, SYS-REQ-118, SW-REQ-105
// STK-REQ-030:STK-REQ-030-AC-03:acceptance
// SW-REQ-105:nominal:nominal
// SW-REQ-105:boundary:nominal
func TestGetRateLimiterStorageReleaseBuild(t *testing.T) {
	conf := Config{
		Storage: StorageOptionsConf{Type: "redis"},
	}

	assert.Same(t, &conf.Storage, conf.GetRateLimiterStorage())
}
