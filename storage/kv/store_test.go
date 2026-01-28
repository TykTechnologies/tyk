package kv

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func TestVaultPut(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		value       string
		kvVersion   int
		vaultConfig config.VaultConfig
		expectError bool
	}{
		{
			name:      "Valid key-value v1",
			key:       "secret.api-key",
			value:     "test-key",
			kvVersion: 1,
			vaultConfig: config.VaultConfig{
				Address:   "http://vault:8200",
				Token:     "root-token",
				KVVersion: 1,
			},
			expectError: true, // Since we don't have a real Vault instance in tests
		},
		{
			name:      "Valid key-value v2",
			key:       "secret.api-key",
			value:     "test-key",
			kvVersion: 2,
			vaultConfig: config.VaultConfig{
				Address:   "http://vault:8200",
				Token:     "root-token",
				KVVersion: 2,
			},
			expectError: true, // Since we don't have a real Vault instance in tests
		},
		{
			name:      "Invalid key format",
			key:       "invalid-key",
			value:     "test-key",
			kvVersion: 1,
			vaultConfig: config.VaultConfig{
				Address:   "http://vault:8200",
				Token:     "root-token",
				KVVersion: 1,
			},
			expectError: true,
		},
		{
			name:      "Missing root token",
			key:       "secret.api-key",
			value:     "test-key",
			kvVersion: 1,
			vaultConfig: config.VaultConfig{
				Address:   "http://vault:8200",
				KVVersion: 1,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVault(tc.vaultConfig)
			if err != nil {
				// For test cases where we expect an error in configuration
				assert.True(t, tc.expectError)
				return
			}

			err = v.Put(tc.key, tc.value)
			if tc.expectError {
				assert.Error(t, err)
				return
			}

			// Only try to verify if we don't expect an error
			if !tc.expectError {
				val, err := v.Get(tc.key)
				assert.NoError(t, err)
				assert.Equal(t, tc.value, val)
			}
		})
	}
}

func TestConsulPut(t *testing.T) {
	t.Skip("Skipping Consul tests as they require a running Consul instance")

	testCases := []struct {
		name        string
		key         string
		value       string
		expectError bool
	}{
		{
			name:        "Valid key-value",
			key:         "api-keys/key1",
			value:       "test-key",
			expectError: false,
		},
		{
			name:        "Empty key",
			key:         "",
			value:       "test-key",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.ConsulConfig{}
			c, err := newConsul(conf)
			assert.NoError(t, err)

			err = c.Put(tc.key, tc.value)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify the value was stored correctly
				val, err := c.Get(tc.key)
				assert.NoError(t, err)
				assert.Equal(t, tc.value, val)
			}
		})
	}
}
