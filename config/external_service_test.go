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
		Global: GlobalProxyConfig{
			Enabled:     true,
			HTTPProxy:   "http://proxy:8080",
			HTTPSProxy:  "https://proxy:8080",
			BypassProxy: "localhost,127.0.0.1",
		},
		OAuth: ServiceConfig{
			Proxy: ProxyConfig{
				Enabled:   true,
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
				Enabled: true,
			},
		},
		Health: ServiceConfig{
			Proxy: ProxyConfig{
				Enabled:   true,
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
	assert.Equal(t, config.Global.Enabled, unmarshaled.Global.Enabled)
	assert.Equal(t, config.Global.HTTPProxy, unmarshaled.Global.HTTPProxy)
	assert.Equal(t, config.Global.HTTPSProxy, unmarshaled.Global.HTTPSProxy)
	assert.Equal(t, config.Global.BypassProxy, unmarshaled.Global.BypassProxy)

	assert.Equal(t, config.OAuth.Proxy.HTTPProxy, unmarshaled.OAuth.Proxy.HTTPProxy)
	assert.Equal(t, config.OAuth.MTLS.Enabled, unmarshaled.OAuth.MTLS.Enabled)
	assert.Equal(t, config.OAuth.MTLS.CertFile, unmarshaled.OAuth.MTLS.CertFile)
	assert.Equal(t, config.OAuth.MTLS.KeyFile, unmarshaled.OAuth.MTLS.KeyFile)
	assert.Equal(t, config.OAuth.MTLS.CAFile, unmarshaled.OAuth.MTLS.CAFile)

	assert.Equal(t, config.Storage.MTLS.Enabled, unmarshaled.Storage.MTLS.Enabled)
	assert.Equal(t, config.Storage.MTLS.InsecureSkipVerify, unmarshaled.Storage.MTLS.InsecureSkipVerify)
	assert.Equal(t, config.Webhooks.Proxy.Enabled, unmarshaled.Webhooks.Proxy.Enabled)
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

	assert.False(t, unmarshaled.Enabled)
	assert.Empty(t, unmarshaled.HTTPProxy)
	assert.Empty(t, unmarshaled.HTTPSProxy)
	assert.Empty(t, unmarshaled.BypassProxy)
}

func TestServiceConfig_Empty(t *testing.T) {
	config := ServiceConfig{}

	// Test that empty configuration doesn't panic
	jsonData, err := json.Marshal(config)
	require.NoError(t, err)

	var unmarshaled ServiceConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.False(t, unmarshaled.Proxy.Enabled)
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
				Global: GlobalProxyConfig{
					Enabled:   true,
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
				Global: GlobalProxyConfig{
					Enabled: true,
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
			if tt.config.Global.HTTPProxy != "" {
				assert.Equal(t, tt.config.Global.HTTPProxy, unmarshaled.Global.HTTPProxy)
			}
			if tt.config.Global.Enabled {
				assert.Equal(t, tt.config.Global.Enabled, unmarshaled.Global.Enabled)
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
		"global": {
			"enabled": true,
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

	assert.True(t, config.Global.Enabled)
	assert.Equal(t, "http://proxy:8080", config.Global.HTTPProxy)
	assert.True(t, config.OAuth.MTLS.Enabled)
	assert.Equal(t, "/cert.pem", config.OAuth.MTLS.CertFile)
}

func TestExternalServiceConfig_JSONTagsWithCertificateStore(t *testing.T) {
	// Test that JSON tags work correctly with new certificate store fields
	jsonStr := `{
		"oauth": {
			"mtls": {
				"enabled": true,
				"cert_id": "cert123",
				"ca_cert_ids": ["ca123", "ca456"],
				"insecure_skip_verify": true,
				"tls_min_version": "1.2",
				"tls_max_version": "1.3"
			}
		},
		"storage": {
			"mtls": {
				"enabled": true,
				"cert_file": "/path/to/cert.pem",
				"key_file": "/path/to/key.pem"
			}
		}
	}`

	var config ExternalServiceConfig
	err := json.Unmarshal([]byte(jsonStr), &config)
	require.NoError(t, err)

	// Test OAuth service with certificate store configuration
	assert.True(t, config.OAuth.MTLS.Enabled)
	assert.Equal(t, "cert123", config.OAuth.MTLS.CertID)
	assert.Equal(t, []string{"ca123", "ca456"}, config.OAuth.MTLS.CACertIDs)
	assert.True(t, config.OAuth.MTLS.InsecureSkipVerify)
	assert.Equal(t, "1.2", config.OAuth.MTLS.TLSMinVersion)
	assert.Equal(t, "1.3", config.OAuth.MTLS.TLSMaxVersion)

	// Test Storage service with file-based configuration (backward compatibility)
	assert.True(t, config.Storage.MTLS.Enabled)
	assert.Equal(t, "/path/to/cert.pem", config.Storage.MTLS.CertFile)
	assert.Equal(t, "/path/to/key.pem", config.Storage.MTLS.KeyFile)

	// Verify that OAuth is certificate store config and Storage is file-based
	assert.True(t, config.OAuth.MTLS.IsCertificateStoreConfig())
	assert.False(t, config.OAuth.MTLS.IsFileBasedConfig())
	assert.False(t, config.Storage.MTLS.IsCertificateStoreConfig())
	assert.True(t, config.Storage.MTLS.IsFileBasedConfig())
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
	assert.False(t, unmarshaled.Global.Enabled)
	assert.Empty(t, unmarshaled.Global.HTTPProxy)
	assert.Empty(t, unmarshaled.Global.HTTPSProxy)
	assert.Empty(t, unmarshaled.Global.BypassProxy)

	assert.False(t, unmarshaled.OAuth.MTLS.Enabled)
	assert.Empty(t, unmarshaled.OAuth.MTLS.CertFile)
	assert.Empty(t, unmarshaled.OAuth.MTLS.KeyFile)
	assert.Empty(t, unmarshaled.OAuth.MTLS.CAFile)
	assert.False(t, unmarshaled.OAuth.MTLS.InsecureSkipVerify)
}

func TestMTLSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      MTLSConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled mTLS should pass validation",
			config: MTLSConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with valid file-based config",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with valid certificate store config",
			config: MTLSConfig{
				Enabled: true,
				CertID:  "cert123",
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with both file and store config should fail",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CertID:   "cert123",
			},
			expectError: true,
			errorMsg:    "cannot specify both file-based and certificate store configuration",
		},
		{
			name: "enabled mTLS with no certificate configuration should fail",
			config: MTLSConfig{
				Enabled: true,
			},
			expectError: true,
			errorMsg:    "mTLS enabled but no certificate configuration provided",
		},
		{
			name: "enabled mTLS with only cert file should fail",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
			},
			expectError: true,
			errorMsg:    "both cert_file and key_file must be specified for file-based configuration",
		},
		{
			name: "enabled mTLS with only key file should fail",
			config: MTLSConfig{
				Enabled: true,
				KeyFile: "/path/to/key.pem",
			},
			expectError: true,
			errorMsg:    "both cert_file and key_file must be specified for file-based configuration",
		},
		{
			name: "enabled mTLS with file config and CA file",
			config: MTLSConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with store config and CA cert IDs",
			config: MTLSConfig{
				Enabled:   true,
				CertID:    "cert123",
				CACertIDs: []string{"ca123", "ca456"},
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with CA file only",
			config: MTLSConfig{
				Enabled: true,
				CAFile:  "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "enabled mTLS with CA cert IDs only",
			config: MTLSConfig{
				Enabled:   true,
				CACertIDs: []string{"ca123", "ca456"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Equal(t, tt.errorMsg, err.Error())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMTLSConfig_IsFileBasedConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   MTLSConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   MTLSConfig{},
			expected: false,
		},
		{
			name: "only cert file",
			config: MTLSConfig{
				CertFile: "/path/to/cert.pem",
			},
			expected: true,
		},
		{
			name: "only key file",
			config: MTLSConfig{
				KeyFile: "/path/to/key.pem",
			},
			expected: true,
		},
		{
			name: "both cert and key files",
			config: MTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			expected: true,
		},
		{
			name: "only cert ID",
			config: MTLSConfig{
				CertID: "cert123",
			},
			expected: false,
		},
		{
			name: "cert file and cert ID",
			config: MTLSConfig{
				CertFile: "/path/to/cert.pem",
				CertID:   "cert123",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsFileBasedConfig()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMTLSConfig_IsCertificateStoreConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   MTLSConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   MTLSConfig{},
			expected: false,
		},
		{
			name: "only cert ID",
			config: MTLSConfig{
				CertID: "cert123",
			},
			expected: true,
		},
		{
			name: "empty cert ID",
			config: MTLSConfig{
				CertID: "",
			},
			expected: false,
		},
		{
			name: "cert ID and file config",
			config: MTLSConfig{
				CertID:   "cert123",
				CertFile: "/path/to/cert.pem",
			},
			expected: true,
		},
		{
			name: "only CA cert IDs",
			config: MTLSConfig{
				CACertIDs: []string{"ca123"},
			},
			expected: false,
		},
		{
			name: "cert ID and CA cert IDs",
			config: MTLSConfig{
				CertID:    "cert123",
				CACertIDs: []string{"ca123", "ca456"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsCertificateStoreConfig()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMTLSConfig_JSONWithCertificateStore(t *testing.T) {
	// Test JSON marshaling/unmarshaling with new certificate store fields
	config := MTLSConfig{
		Enabled:            true,
		CertID:             "cert123",
		CACertIDs:          []string{"ca123", "ca456"},
		InsecureSkipVerify: false,
		TLSMinVersion:      "1.2",
		TLSMaxVersion:      "1.3",
	}

	jsonData, err := json.Marshal(config)
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), "cert123")
	assert.Contains(t, string(jsonData), "ca123")
	assert.Contains(t, string(jsonData), "ca456")

	var unmarshaled MTLSConfig
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, config.Enabled, unmarshaled.Enabled)
	assert.Equal(t, config.CertID, unmarshaled.CertID)
	assert.Equal(t, config.CACertIDs, unmarshaled.CACertIDs)
	assert.Equal(t, config.InsecureSkipVerify, unmarshaled.InsecureSkipVerify)
	assert.Equal(t, config.TLSMinVersion, unmarshaled.TLSMinVersion)
	assert.Equal(t, config.TLSMaxVersion, unmarshaled.TLSMaxVersion)
}
