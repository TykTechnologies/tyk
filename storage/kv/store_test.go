package kv

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// STK-REQ-096:STK-REQ-096-AC-01:acceptance
// STK-REQ-096:error_handling:negative
// SYS-REQ-184:nominal:nominal
// SYS-REQ-184:boundary:nominal
// SYS-REQ-184:error_handling:nominal
// SYS-REQ-184:error_handling:negative
// SYS-REQ-184:encoding_safety:nominal
// SYS-REQ-184:determinism:nominal
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:error_handling:negative
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
func TestVaultPut(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		value       string
		kvVersion   int
		expectPath  string
		expectBody  map[string]interface{}
		expectError string
	}{
		{
			name:       "Valid key-value v1",
			key:        "secret.api-key",
			value:      "test-key",
			kvVersion:  1,
			expectPath: "/v1/secret",
			expectBody: map[string]interface{}{
				"api-key": "test-key",
			},
		},
		{
			name:       "Valid key-value v2",
			key:        "secret/api.api-key",
			value:      "test-key",
			kvVersion:  2,
			expectPath: "/v1/secret/data/api",
			expectBody: map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			},
		},
		{
			name:        "Invalid key format",
			key:         "invalid-key",
			value:       "test-key",
			kvVersion:   1,
			expectError: "key should be in form of config.value",
		},
		{
			name:        "Missing root token",
			key:         "secret.api-key",
			value:       "test-key",
			kvVersion:   1,
			expectError: "you must provide a root token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requested := false
			mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested = true
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, tc.expectPath, r.URL.Path)
				assert.Equal(t, "root-token", r.Header.Get("X-Vault-Token"))

				var body map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, tc.expectBody, body)
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}}))
			}))
			defer mockVault.Close()

			conf := config.VaultConfig{
				Address:   mockVault.URL,
				Token:     "root-token",
				KVVersion: tc.kvVersion,
			}
			if strings.Contains(tc.name, "Missing root token") {
				conf.Token = ""
			}

			v, err := NewVault(conf)
			if err != nil {
				require.NotEmpty(t, tc.expectError)
				assert.Contains(t, err.Error(), tc.expectError)
				assert.False(t, requested)
				return
			}

			err = v.Put(tc.key, tc.value)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
				assert.False(t, requested)
				return
			}

			assert.NoError(t, err)
			assert.True(t, requested)
		})
	}
}

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:error_handling:negative
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
func TestVaultGet(t *testing.T) {
	testCases := []struct {
		name        string
		key         string
		kvVersion   int
		response    map[string]interface{}
		statusCode  int
		expectPath  string
		expectValue string
		expectError error
		errorText   string
	}{
		{
			name:      "Valid key-value v1",
			key:       "secret.api-key",
			kvVersion: 1,
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			},
			statusCode:  http.StatusOK,
			expectPath:  "/v1/secret",
			expectValue: "test-key",
		},
		{
			name:      "Valid key-value v2",
			key:       "secret/api.api-key",
			kvVersion: 2,
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"api-key": "test-key",
					},
				},
			},
			statusCode:  http.StatusOK,
			expectPath:  "/v1/secret/data/api",
			expectValue: "test-key",
		},
		{
			name:      "Invalid key format",
			key:       "invalid-key",
			kvVersion: 1,
			errorText: "key should be in form of config.value",
		},
		{
			name:        "Missing secret",
			key:         "secret.api-key",
			kvVersion:   1,
			statusCode:  http.StatusNotFound,
			expectPath:  "/v1/secret",
			expectError: ErrKeyNotFound,
		},
		{
			name:      "Missing field",
			key:       "secret.missing-key",
			kvVersion: 1,
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			},
			statusCode:  http.StatusOK,
			expectPath:  "/v1/secret",
			expectError: ErrKeyNotFound,
		},
		{
			name:      "Missing v2 data wrapper",
			key:       "secret/api.api-key",
			kvVersion: 2,
			response: map[string]interface{}{
				"data": map[string]interface{}{
					"api-key": "test-key",
				},
			},
			statusCode:  http.StatusOK,
			expectPath:  "/v1/secret/data/api",
			expectError: ErrKeyNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requested := false
			mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested = true
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, tc.expectPath, r.URL.Path)
				assert.Equal(t, "root-token", r.Header.Get("X-Vault-Token"))

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				if tc.response != nil {
					require.NoError(t, json.NewEncoder(w).Encode(tc.response))
				}
			}))
			defer mockVault.Close()

			v, err := NewVault(config.VaultConfig{
				Address:   mockVault.URL,
				Token:     "root-token",
				KVVersion: tc.kvVersion,
			})
			require.NoError(t, err)

			value, err := v.Get(tc.key)
			if tc.expectError != nil || tc.errorText != "" {
				if tc.expectError != nil {
					assert.ErrorIs(t, err, tc.expectError)
				} else {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tc.errorText)
				}
				assert.Empty(t, value)
				if tc.expectPath == "" {
					assert.False(t, requested)
				} else {
					assert.True(t, requested)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectValue, value)
			assert.True(t, requested)
		})
	}
}

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:error_handling:negative
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
func TestConsulPut(t *testing.T) {
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
			consulURL, values, closeServer := newTestConsulServer(t)
			defer closeServer()

			conf := consulConfigForURL(t, consulURL)
			c, err := newConsul(conf)
			assert.NoError(t, err)

			err = c.Put(tc.key, tc.value)
			if tc.expectError {
				assert.Error(t, err)
				_, ok := values[tc.key]
				assert.False(t, ok)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.value, values[tc.key])
				val, err := c.Get(tc.key)
				assert.NoError(t, err)
				assert.Equal(t, tc.value, val)
			}
		})
	}
}

// Verifies: STK-REQ-096, SYS-REQ-184, SW-REQ-171
// SW-REQ-171:nominal:nominal
// SW-REQ-171:boundary:nominal
// SW-REQ-171:error_handling:nominal
// SW-REQ-171:error_handling:negative
// SW-REQ-171:encoding_safety:nominal
// SW-REQ-171:determinism:nominal
func TestVaultReadSecret(t *testing.T) {
	t.Run("ReadSecret returns secret from Vault", func(t *testing.T) {
		mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/secret/data/tyk-apis", r.URL.Path)

			response := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"api-key": "secret-value",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(response))
		}))
		defer mockVault.Close()

		v, err := NewVault(config.VaultConfig{
			Address:   mockVault.URL,
			Token:     "test-token",
			KVVersion: 2,
		})
		assert.NoError(t, err)

		vault := v.(*Vault)
		secret, err := vault.ReadSecret("secret/data/tyk-apis")

		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.NotNil(t, secret.Data["data"])
	})

	t.Run("ReadSecret returns nil for non-existent path", func(t *testing.T) {
		mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockVault.Close()

		v, err := NewVault(config.VaultConfig{
			Address:   mockVault.URL,
			Token:     "test-token",
			KVVersion: 2,
		})
		assert.NoError(t, err)

		vault := v.(*Vault)
		secret, err := vault.ReadSecret("secret/data/non-existent")

		assert.NoError(t, err)
		assert.Nil(t, secret)
	})

	t.Run("ReadSecret returns error on server error", func(t *testing.T) {
		mockVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer mockVault.Close()

		v, err := NewVault(config.VaultConfig{
			Address:   mockVault.URL,
			Token:     "test-token",
			KVVersion: 2,
		})
		assert.NoError(t, err)

		vault := v.(*Vault)
		secret, err := vault.ReadSecret("secret/data/tyk-apis")

		assert.Error(t, err)
		assert.Nil(t, secret)
	})
}

func newTestConsulServer(t *testing.T) (string, map[string]string, func()) {
	t.Helper()

	values := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/kv/")
		switch r.Method {
		case http.MethodGet:
			value, ok := values[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			response := []map[string]interface{}{
				{
					"Key":   key,
					"Value": base64.StdEncoding.EncodeToString([]byte(value)),
				},
			}
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(response))
		case http.MethodPut:
			if key == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			values[key] = string(body)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(true))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	return server.URL, values, server.Close
}

func consulConfigForURL(t *testing.T, rawURL string) config.ConsulConfig {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return config.ConsulConfig{
		Address: u.Host,
		Scheme:  u.Scheme,
	}
}
