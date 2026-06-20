package rate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/redis"
)

// Verifies: SW-REQ-016
// SW-REQ-016:nominal:nominal
// SW-REQ-016:boundary:nominal
// SW-REQ-016:boundary:boundary
func TestNewStorage(t *testing.T) {
	baseConfig := func() config.StorageOptionsConf {
		return config.StorageOptionsConf{
			Addrs:                 []string{"redis-1:6379", "redis-2:6379"},
			Username:              "rate-user",
			Password:              "rate-pass",
			Database:              3,
			MaxActive:             100,
			Timeout:               4,
			UseSSL:                true,
			SSLInsecureSkipVerify: true,
			SentinelPassword:      "sentinel-pass",
		}
	}

	t.Run("creates simple client with configured options", func(t *testing.T) {
		cfg := baseConfig()

		client := NewStorage(&cfg, nil)
		t.Cleanup(func() { _ = client.Close() })

		simple, ok := client.(*redis.Client)
		require.True(t, ok)

		opts := simple.Options()
		assert.Equal(t, "redis-1:6379", opts.Addr)
		assert.Equal(t, "rate-user", opts.Username)
		assert.Equal(t, "rate-pass", opts.Password)
		assert.Equal(t, 3, opts.DB)
		assert.Equal(t, 100, opts.PoolSize)
		assert.Equal(t, 4*time.Second, opts.DialTimeout)
		assert.Equal(t, 4*time.Second, opts.ReadTimeout)
		assert.Equal(t, 4*time.Second, opts.WriteTimeout)
		require.NotNil(t, opts.TLSConfig)
		assert.True(t, opts.TLSConfig.InsecureSkipVerify)
	})

	t.Run("creates cluster client when cluster is enabled", func(t *testing.T) {
		cfg := baseConfig()
		cfg.EnableCluster = true

		client := NewStorage(&cfg, nil)
		t.Cleanup(func() { _ = client.Close() })

		cluster, ok := client.(*redis.ClusterClient)
		require.True(t, ok)

		opts := cluster.Options()
		assert.Equal(t, []string{"redis-1:6379", "redis-2:6379"}, opts.Addrs)
		assert.Equal(t, "rate-user", opts.Username)
		assert.Equal(t, "rate-pass", opts.Password)
		assert.Equal(t, 100, opts.PoolSize)
		assert.Equal(t, 4*time.Second, opts.DialTimeout)
		assert.Equal(t, 4*time.Second, opts.ReadTimeout)
		assert.Equal(t, 4*time.Second, opts.WriteTimeout)
		require.NotNil(t, opts.TLSConfig)
		assert.True(t, opts.TLSConfig.InsecureSkipVerify)
	})

	t.Run("sentinel master selection takes precedence over cluster", func(t *testing.T) {
		cfg := baseConfig()
		cfg.EnableCluster = true
		cfg.MasterName = "redis-master"

		client := NewStorage(&cfg, nil)
		t.Cleanup(func() { _ = client.Close() })

		_, isCluster := client.(*redis.ClusterClient)
		assert.False(t, isCluster)

		sentinel, ok := client.(*redis.Client)
		require.True(t, ok)
		assert.Equal(t, "rate-user", sentinel.Options().Username)
	})

	t.Run("uses default pool and timeout when unset", func(t *testing.T) {
		cfg := config.StorageOptionsConf{
			Host: "redis",
			Port: 6379,
		}

		client := NewStorage(&cfg, nil)
		t.Cleanup(func() { _ = client.Close() })

		simple, ok := client.(*redis.Client)
		require.True(t, ok)

		opts := simple.Options()
		assert.Equal(t, "redis:6379", opts.Addr)
		assert.Equal(t, 500, opts.PoolSize)
		assert.Equal(t, 5*time.Second, opts.DialTimeout)
		assert.Nil(t, opts.TLSConfig)
	})
}

// Verifies: SW-REQ-016
// SW-REQ-016:nominal:nominal
// SW-REQ-016:boundary:nominal
// SW-REQ-016:boundary:boundary
// SW-REQ-016:error_handling:nominal
// SW-REQ-016:error_handling:negative
func TestCreateTLSConfig_ExternalServicesIntegration(t *testing.T) {
	// Test that external services storage configuration overrides legacy config

	// Legacy storage config
	storageConf := &config.StorageOptionsConf{
		SSLInsecureSkipVerify: false, // Will be overridden
		CAFile:                "/legacy/ca.crt",
		CertFile:              "/legacy/client.crt",
		KeyFile:               "/legacy/client.key",
	}

	// External services config with mTLS enabled
	externalServicesConfig := &config.ExternalServiceConfig{
		Storage: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true, // Should override legacy false
				CertFile:           "/external/storage-client.crt",
				KeyFile:            "/external/storage-client.key",
				CAFile:             "/external/storage-ca.crt",
			},
		},
	}

	// Test with external services config - should use external config
	tlsConfig := createTLSConfig(storageConf, externalServicesConfig)
	assert.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify, "Should use external services InsecureSkipVerify=true")

	// Test without external services config - should use legacy config
	tlsConfigLegacy := createTLSConfig(storageConf, nil)
	assert.NotNil(t, tlsConfigLegacy)
	assert.False(t, tlsConfigLegacy.InsecureSkipVerify, "Should use legacy InsecureSkipVerify=false")

	// Test with external services config disabled - should use legacy config
	externalServicesConfigDisabled := &config.ExternalServiceConfig{
		Storage: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled: false, // Disabled
			},
		},
	}
	tlsConfigDisabled := createTLSConfig(storageConf, externalServicesConfigDisabled)
	assert.NotNil(t, tlsConfigDisabled)
	assert.False(t, tlsConfigDisabled.InsecureSkipVerify, "Should use legacy config when external services mTLS disabled")
}

// Verifies: SW-REQ-016
// SW-REQ-016:nominal:nominal
// SW-REQ-016:boundary:nominal
// SW-REQ-016:boundary:boundary
// SW-REQ-016:error_handling:nominal
// SW-REQ-016:error_handling:negative
func TestCreateTLSConfig_TLSVersions(t *testing.T) {
	// Test TLS version configuration with external services

	// Legacy storage config with TLS versions
	storageConf := &config.StorageOptionsConf{
		SSLInsecureSkipVerify: false,
		TLSMinVersion:         "1.0", // Will be overridden by external services
		TLSMaxVersion:         "1.2", // Will be overridden by external services
	}

	// External services config with different TLS versions
	externalServicesConfig := &config.ExternalServiceConfig{
		Storage: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: false,
				TLSMinVersion:      "1.2", // Should override legacy "1.0"
				TLSMaxVersion:      "1.3", // Should override legacy "1.2"
			},
		},
	}

	// Test with external services config - should use external TLS versions
	tlsConfig := createTLSConfig(storageConf, externalServicesConfig)
	assert.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(0x0303), tlsConfig.MinVersion, "Should use external services TLSMinVersion=1.2 (0x0303)")
	assert.Equal(t, uint16(0x0304), tlsConfig.MaxVersion, "Should use external services TLSMaxVersion=1.3 (0x0304)")

	// Test without external services config - should use legacy TLS versions
	tlsConfigLegacy := createTLSConfig(storageConf, nil)
	assert.NotNil(t, tlsConfigLegacy)
	assert.Equal(t, uint16(0x0301), tlsConfigLegacy.MinVersion, "Should use legacy TLSMinVersion=1.0 (0x0301)")
	assert.Equal(t, uint16(0x0303), tlsConfigLegacy.MaxVersion, "Should use legacy TLSMaxVersion=1.2 (0x0303)")

	// Test external services with only min version set
	externalServicesMinOnly := &config.ExternalServiceConfig{
		Storage: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:       true,
				TLSMinVersion: "1.3", // Only set min version
			},
		},
	}

	tlsConfigMinOnly := createTLSConfig(storageConf, externalServicesMinOnly)
	assert.NotNil(t, tlsConfigMinOnly)
	assert.Equal(t, uint16(0x0304), tlsConfigMinOnly.MinVersion, "Should use external services TLSMinVersion=1.3")
	assert.Equal(t, uint16(0x0), tlsConfigMinOnly.MaxVersion, "MaxVersion should be 0 (not set)")

	// Test external services with invalid TLS version
	externalServicesInvalid := &config.ExternalServiceConfig{
		Storage: config.ServiceConfig{
			MTLS: config.MTLSConfig{
				Enabled:       true,
				TLSMinVersion: "invalid", // Invalid version
				TLSMaxVersion: "1.2",     // Valid version
			},
		},
	}

	tlsConfigInvalid := createTLSConfig(storageConf, externalServicesInvalid)
	assert.NotNil(t, tlsConfigInvalid)
	assert.Equal(t, uint16(0x0), tlsConfigInvalid.MinVersion, "Invalid TLS version should result in 0 (not set)")
	assert.Equal(t, uint16(0x0303), tlsConfigInvalid.MaxVersion, "Valid TLS version should be set")
}
