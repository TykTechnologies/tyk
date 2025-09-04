package rate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func TestNewStorage(t *testing.T) {
	conf, err := config.NewDefaultWithEnv()
	assert.NoError(t, err)

	// Coverage
	conf.Storage.MaxActive = 100
	conf.Storage.Timeout = 4
	conf.Storage.UseSSL = true

	client := NewStorage(&conf.Storage, nil)
	assert.NotNil(t, client)

	conf.Storage.EnableCluster = true
	client = NewStorage(&conf.Storage, nil)
	assert.NotNil(t, client)

	conf.Storage.EnableCluster = false
	conf.Storage.MasterName = "redis"
	client = NewStorage(&conf.Storage, nil)
	assert.NotNil(t, client)
}

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
