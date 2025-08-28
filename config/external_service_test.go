package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalServiceConfig_JSON(t *testing.T) {
	// Test serialization and deserialization of the configuration
	config := ExternalServiceConfig{
		Proxy: ProxyConfig{
			UseEnvironment: true,
			HTTPProxy:      "http://proxy:8080",
			HTTPSProxy:     "https://proxy:8080",
			NoProxy:        "localhost,127.0.0.1",
		},
		OAuth: ServiceConfig{
			Proxy: ProxyConfig{
				HTTPProxy: "http://oauth-proxy:8080",
			},
			MTLS: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
		},
		Storage: ServiceConfig{
			MTLS: MTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
				TLSMinVersion:      "1.2",
				TLSMaxVersion:      "1.3",
			},
		},
		Webhooks: ServiceConfig{
			Proxy: ProxyConfig{
				UseEnvironment: true,
			},
		},
		Health: ServiceConfig{
			Proxy: ProxyConfig{
				HTTPProxy: "http://health-proxy:8080",
			},
		},
		Discovery: ServiceConfig{
			MTLS: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/discovery-cert.pem",
				KeyFile:  "/path/to/discovery-key.pem",
			},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(config)
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), "http://proxy:8080")
	assert.Contains(t, string(jsonData), "oauth-proxy:8080")

	// Test JSON unmarshaling
	var unmarshaled ExternalServiceConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	// Verify all fields are correctly unmarshaled
	assert.Equal(t, config.Proxy.UseEnvironment, unmarshaled.Proxy.UseEnvironment)
	assert.Equal(t, config.Proxy.HTTPProxy, unmarshaled.Proxy.HTTPProxy)
	assert.Equal(t, config.Proxy.HTTPSProxy, unmarshaled.Proxy.HTTPSProxy)
	assert.Equal(t, config.Proxy.NoProxy, unmarshaled.Proxy.NoProxy)

	assert.Equal(t, config.OAuth.Proxy.HTTPProxy, unmarshaled.OAuth.Proxy.HTTPProxy)
	assert.Equal(t, config.OAuth.MTLS.Enabled, unmarshaled.OAuth.MTLS.Enabled)
	assert.Equal(t, config.OAuth.MTLS.CertFile, unmarshaled.OAuth.MTLS.CertFile)
	assert.Equal(t, config.OAuth.MTLS.KeyFile, unmarshaled.OAuth.MTLS.KeyFile)
	assert.Equal(t, config.OAuth.MTLS.CAFile, unmarshaled.OAuth.MTLS.CAFile)

	assert.Equal(t, config.Storage.MTLS.Enabled, unmarshaled.Storage.MTLS.Enabled)
	assert.Equal(t, config.Storage.MTLS.InsecureSkipVerify, unmarshaled.Storage.MTLS.InsecureSkipVerify)
	assert.Equal(t, config.Webhooks.Proxy.UseEnvironment, unmarshaled.Webhooks.Proxy.UseEnvironment)
	assert.Equal(t, config.Health.Proxy.HTTPProxy, unmarshaled.Health.Proxy.HTTPProxy)
	assert.Equal(t, config.Discovery.MTLS.Enabled, unmarshaled.Discovery.MTLS.Enabled)
	assert.Equal(t, config.Discovery.MTLS.CertFile, unmarshaled.Discovery.MTLS.CertFile)
	assert.Equal(t, config.Discovery.MTLS.KeyFile, unmarshaled.Discovery.MTLS.KeyFile)
}

func TestProxyConfig_Empty(t *testing.T) {
	config := ProxyConfig{}

	// Test that empty configuration doesn't panic
	jsonData, err := json.Marshal(config)
	require.NoError(t, err)

	var unmarshaled ProxyConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.False(t, unmarshaled.UseEnvironment)
	assert.Empty(t, unmarshaled.HTTPProxy)
	assert.Empty(t, unmarshaled.HTTPSProxy)
	assert.Empty(t, unmarshaled.NoProxy)
}

func TestServiceConfig_Empty(t *testing.T) {
	config := ServiceConfig{}

	// Test that empty configuration doesn't panic
	jsonData, err := json.Marshal(config)
	require.NoError(t, err)

	var unmarshaled ServiceConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.False(t, unmarshaled.Proxy.UseEnvironment)
	assert.Empty(t, unmarshaled.Proxy.HTTPProxy)
	assert.False(t, unmarshaled.MTLS.Enabled)
	assert.Empty(t, unmarshaled.MTLS.CertFile)
}

func TestMTLSConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config MTLSConfig
		valid  bool
	}{
		{
			name: "disabled mTLS",
			config: MTLSConfig{
				Enabled: false,
			},
			valid: true,
		},
		{
			name: "enabled mTLS with cert and key",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			valid: true,
		},
		{
			name: "enabled mTLS with cert, key, and CA",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
			valid: true,
		},
		{
			name: "enabled mTLS with insecure skip verify",
			config: MTLSConfig{
				Enabled:            true,
				CertFile:           "/path/to/cert.pem",
				KeyFile:            "/path/to/key.pem",
				InsecureSkipVerify: true,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling/unmarshaling
			jsonData, err := json.Marshal(tt.config)
			require.NoError(t, err)

			var unmarshaled MTLSConfig
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.config.Enabled, unmarshaled.Enabled)
			assert.Equal(t, tt.config.CertFile, unmarshaled.CertFile)
			assert.Equal(t, tt.config.KeyFile, unmarshaled.KeyFile)
			assert.Equal(t, tt.config.CAFile, unmarshaled.CAFile)
			assert.Equal(t, tt.config.InsecureSkipVerify, unmarshaled.InsecureSkipVerify)
		})
	}
}

func TestServiceTypeConstants(t *testing.T) {
	// Test that all service type constants are defined correctly
	expectedTypes := map[string]string{
		ServiceTypeOAuth:     "oauth",
		ServiceTypeStorage:   "storage",
		ServiceTypeWebhook:   "webhook",
		ServiceTypeHealth:    "health",
		ServiceTypeDiscovery: "discovery",
	}

	for constant, expected := range expectedTypes {
		assert.Equal(t, expected, constant, "Service type constant %s should equal %s", constant, expected)
	}
}

func TestExternalServiceConfig_PartialConfiguration(t *testing.T) {
	// Test various partial configurations that might be common in real usage
	tests := []struct {
		name   string
		config ExternalServiceConfig
	}{
		{
			name: "only global proxy",
			config: ExternalServiceConfig{
				Proxy: ProxyConfig{
					HTTPProxy: "http://proxy:8080",
				},
			},
		},
		{
			name: "only OAuth service config",
			config: ExternalServiceConfig{
				OAuth: ServiceConfig{
					MTLS: MTLSConfig{
						Enabled:  true,
						CertFile: "/path/to/cert.pem",
						KeyFile:  "/path/to/key.pem",
					},
				},
			},
		},
		{
			name: "mixed configuration",
			config: ExternalServiceConfig{
				Proxy: ProxyConfig{
					UseEnvironment: true,
				},
				Webhooks: ServiceConfig{
					MTLS: MTLSConfig{
						Enabled:            true,
						InsecureSkipVerify: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that partial configurations can be marshaled and unmarshaled
			jsonData, err := json.Marshal(tt.config)
			require.NoError(t, err)

			var unmarshaled ExternalServiceConfig
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			// Verify specific fields that were set
			if tt.config.Proxy.HTTPProxy != "" {
				assert.Equal(t, tt.config.Proxy.HTTPProxy, unmarshaled.Proxy.HTTPProxy)
			}
			if tt.config.Proxy.UseEnvironment {
				assert.Equal(t, tt.config.Proxy.UseEnvironment, unmarshaled.Proxy.UseEnvironment)
			}
			if tt.config.OAuth.MTLS.Enabled {
				assert.Equal(t, tt.config.OAuth.MTLS.Enabled, unmarshaled.OAuth.MTLS.Enabled)
			}
			if tt.config.Webhooks.MTLS.Enabled {
				assert.Equal(t, tt.config.Webhooks.MTLS.Enabled, unmarshaled.Webhooks.MTLS.Enabled)
			}
		})
	}
}

func TestExternalServiceConfig_JSONTags(t *testing.T) {
	// Test that JSON tags are working correctly by creating a minimal JSON and unmarshaling
	jsonStr := `{
		"proxy": {
			"use_environment": true,
			"http_proxy": "http://proxy:8080"
		},
		"oauth": {
			"mtls": {
				"enabled": true,
				"cert_file": "/cert.pem"
			}
		}
	}`

	var config ExternalServiceConfig
	err := json.Unmarshal([]byte(jsonStr), &config)
	require.NoError(t, err)

	assert.True(t, config.Proxy.UseEnvironment)
	assert.Equal(t, "http://proxy:8080", config.Proxy.HTTPProxy)
	assert.True(t, config.OAuth.MTLS.Enabled)
	assert.Equal(t, "/cert.pem", config.OAuth.MTLS.CertFile)
}

func TestExternalServiceConfig_ZeroValues(t *testing.T) {
	// Test that zero values are handled correctly
	var config ExternalServiceConfig

	jsonData, err := json.Marshal(config)
	require.NoError(t, err)

	var unmarshaled ExternalServiceConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	// All fields should be zero values
	assert.False(t, unmarshaled.Proxy.UseEnvironment)
	assert.Empty(t, unmarshaled.Proxy.HTTPProxy)
	assert.Empty(t, unmarshaled.Proxy.HTTPSProxy)
	assert.Empty(t, unmarshaled.Proxy.NoProxy)

	assert.False(t, unmarshaled.OAuth.MTLS.Enabled)
	assert.Empty(t, unmarshaled.OAuth.MTLS.CertFile)
	assert.Empty(t, unmarshaled.OAuth.MTLS.KeyFile)
	assert.Empty(t, unmarshaled.OAuth.MTLS.CAFile)
	assert.False(t, unmarshaled.OAuth.MTLS.InsecureSkipVerify)
}
