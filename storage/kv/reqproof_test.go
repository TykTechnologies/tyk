package kv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// STK-REQ-096:STK-REQ-096-AC-01:acceptance
// SYS-REQ-184:nominal:nominal
// SYS-REQ-184:boundary:nominal
// SYS-REQ-184:error_handling:nominal
// SYS-REQ-184:encoding_safety:nominal
// SYS-REQ-184:determinism:nominal
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
// MCDC SYS-REQ-184: storage_kv_consul_config_determined=T, storage_kv_consul_read_write_determined=T, storage_kv_vault_config_determined=T, storage_kv_vault_get_determined=T, storage_kv_vault_put_determined=T, storage_kv_vault_read_secret_determined=T => TRUE
// MCDC SW-REQ-171: storage_kv_consul_config_determined=T, storage_kv_consul_read_write_determined=T, storage_kv_vault_config_determined=T, storage_kv_vault_get_determined=T, storage_kv_vault_put_determined=T, storage_kv_vault_read_secret_determined=T => TRUE
func TestStorageKVReqProof(t *testing.T) {
	consulURL, consulValues, closeConsul := newTestConsulServer(t)
	defer closeConsul()

	consulStore, err := NewConsul(consulConfigForURL(t, consulURL))
	require.NoError(t, err)
	consul, ok := consulStore.(*Consul)
	require.True(t, ok)
	assert.NotNil(t, consul.Store())

	_, err = consulStore.Get("api-keys/missing")
	assert.ErrorIs(t, err, ErrKeyNotFound)

	require.NoError(t, consulStore.Put("api-keys/key1", "test-key"))
	assert.Equal(t, "test-key", consulValues["api-keys/key1"])

	consulValue, err := consulStore.Get("api-keys/key1")
	require.NoError(t, err)
	assert.Equal(t, "test-key", consulValue)

	vaultRequests := map[string]int{}
	mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultRequests[r.Method+" "+r.URL.Path]++
		assert.Equal(t, "root-token", r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")

		switch r.Method + " " + r.URL.Path {
		case http.MethodPut + " /v1/secret":
			assertVaultBody(t, r, map[string]interface{}{
				"api-key": "test-key",
			})
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}}))
		case http.MethodPut + " /v1/secret/data/api":
			assertVaultBody(t, r, map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			})
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}}))
		case http.MethodGet + " /v1/secret":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			}))
		case http.MethodGet + " /v1/secret/data/api":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"api-key": "test-key",
					},
				},
			}))
		case http.MethodGet + " /v1/secret/data/tyk-apis":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"api-key": "secret-value",
					},
				},
			}))
		case http.MethodGet + " /v1/secret/data/missing":
			w.WriteHeader(http.StatusNotFound)
		case http.MethodGet + " /v1/secret/data/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockVault.Close()

	_, err = NewVault(config.VaultConfig{Address: mockVault.URL, KVVersion: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "you must provide a root token")

	vaultCases := []struct {
		name      string
		key       string
		kvVersion int
	}{
		{
			name:      "v1",
			key:       "secret.api-key",
			kvVersion: 1,
		},
		{
			name:      "v2",
			key:       "secret/api.api-key",
			kvVersion: 2,
		},
	}

	for _, tc := range vaultCases {
		t.Run(tc.name, func(t *testing.T) {
			vaultStore, err := NewVault(config.VaultConfig{
				Address:   mockVault.URL,
				Token:     "root-token",
				KVVersion: tc.kvVersion,
			})
			require.NoError(t, err)

			vault, ok := vaultStore.(*Vault)
			require.True(t, ok)
			assert.Equal(t, "root-token", vault.Client().Token())

			require.NoError(t, vaultStore.Put(tc.key, "test-key"))

			vaultValue, err := vaultStore.Get(tc.key)
			require.NoError(t, err)
			assert.Equal(t, "test-key", vaultValue)

			_, err = vaultStore.Get("invalid-key")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "key should be in form of config.value")

			err = vaultStore.Put("invalid-key", "test-key")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "key should be in form of config.value")
		})
	}

	vaultStore, err := NewVault(config.VaultConfig{
		Address:   mockVault.URL,
		Token:     "root-token",
		KVVersion: 2,
	})
	require.NoError(t, err)
	vault := vaultStore.(*Vault)

	secret, err := vault.ReadSecret("secret/data/tyk-apis")
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.NotNil(t, secret.Data["data"])

	secret, err = vault.ReadSecret("secret/data/missing")
	require.NoError(t, err)
	assert.Nil(t, secret)

	secret, err = vault.ReadSecret("secret/data/error")
	require.Error(t, err)
	assert.Nil(t, secret)

	for _, request := range []string{
		http.MethodPut + " /v1/secret",
		http.MethodGet + " /v1/secret",
		http.MethodPut + " /v1/secret/data/api",
		http.MethodGet + " /v1/secret/data/api",
		http.MethodGet + " /v1/secret/data/tyk-apis",
		http.MethodGet + " /v1/secret/data/missing",
		http.MethodGet + " /v1/secret/data/error",
	} {
		assert.Greater(t, vaultRequests[request], 0, request)
	}
}

func assertVaultBody(t *testing.T, r *http.Request, expected map[string]interface{}) {
	t.Helper()

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
	assert.Equal(t, expected, body)
}
