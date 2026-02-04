package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/structviewer"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func TestConfigInspectionEndpoints_Disabled(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = false
	})
	defer ts.Close()

	// /config should return 404 when disabled
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config",
		AdminAuth: true,
		Code:      http.StatusNotFound,
	})

	// /env should return 404 when disabled
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env",
		AdminAuth: true,
		Code:      http.StatusNotFound,
	})
}

func TestConfigInspectionEndpoints_EnabledWithoutSecret(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = ""
	})
	defer ts.Close()

	// /config should return 404 when secret is not set (endpoints not registered)
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config",
		AdminAuth: true,
		Code:      http.StatusNotFound,
	})
}

func TestConfigInspectionEndpoints_AuthRequired(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	// /config without auth header should return 403
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config",
		AdminAuth: false,
		Code:      http.StatusForbidden,
	})

	// /config with wrong auth header should return 403
	_, _ = ts.Run(t, test.TestCase{
		Method:  http.MethodGet,
		Path:    "/config",
		Headers: map[string]string{"X-Tyk-Authorization": "wrong-secret"},
		Code:    http.StatusForbidden,
	})

	// /env without auth header should return 403
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env",
		AdminAuth: false,
		Code:      http.StatusForbidden,
	})
}

func TestConfigHandler_FullConfig(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.ListenPort = 9999
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var configResp map[string]interface{}
			err := json.Unmarshal(resp, &configResp)
			assert.NoError(t, err)

			// Verify listen_port is in response
			assert.Equal(t, float64(9999), configResp["listen_port"])

			// Verify secret is redacted (should be empty string or redacted marker)
			secret, ok := configResp["secret"]
			assert.True(t, ok, "secret field should be present")
			// structviewer redacts string fields by setting them to empty or "*REDACTED*"
			assert.NotEqual(t, "test-secret", secret, "secret should be redacted")
			return true
		},
	})
}

func TestConfigHandler_SingleField(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.ListenPort = 8888
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=listen_port",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify response contains expected fields
			assert.Equal(t, "listen_port", fieldResp["config_field"])
			assert.Equal(t, "TYK_GW_LISTENPORT", fieldResp["env"])
			// structviewer returns values as strings
			assert.Equal(t, "8888", fieldResp["value"])
			assert.Equal(t, false, fieldResp["obfuscated"])
			return true
		},
	})
}

func TestConfigHandler_SingleField_NotFound(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=nonexistent_field",
		AdminAuth: true,
		Code:      http.StatusNotFound,
		BodyMatchFunc: func(resp []byte) bool {
			var errResp map[string]string
			err := json.Unmarshal(resp, &errResp)
			assert.NoError(t, err)
			assert.Equal(t, "field not found", errResp["error"])
			return true
		},
	})
}

func TestConfigHandler_SensitiveFieldRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "super-secret-value"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=secret",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify field is marked as obfuscated
			assert.Equal(t, true, fieldResp["obfuscated"])
			// Value should NOT be the actual secret
			assert.NotEqual(t, "super-secret-value", fieldResp["value"])
			return true
		},
	})
}

func TestEnvHandler_AllEnvVars(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			// The /env endpoint returns an array of env var strings like "TYK_GW_VAR=value"
			var envResp []string
			err := json.Unmarshal(resp, &envResp)
			assert.NoError(t, err)

			// Should return an array of env var mappings
			assert.Greater(t, len(envResp), 0, "should have at least one env var mapping")

			// Verify we have TYK_GW_ prefix env vars (structviewer generates these)
			var foundTykGwEnvVar bool
			for _, env := range envResp {
				if len(env) > 7 && env[:7] == "TYK_GW_" {
					foundTykGwEnvVar = true
					break
				}
			}
			assert.True(t, foundTykGwEnvVar, "Should have at least one TYK_GW_* env var")
			return true
		},
	})
}

func TestEnvHandler_SingleEnvVar(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.ListenPort = 7777
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env?env=TYK_GW_LISTENPORT",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var envResp map[string]interface{}
			err := json.Unmarshal(resp, &envResp)
			assert.NoError(t, err)

			assert.Equal(t, "listen_port", envResp["config_field"])
			assert.Equal(t, "TYK_GW_LISTENPORT", envResp["env"])
			// structviewer returns values as strings
			assert.Equal(t, "7777", envResp["value"])
			assert.Equal(t, false, envResp["obfuscated"])
			return true
		},
	})
}

func TestEnvHandler_SingleEnvVar_NotFound(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env?env=TYK_GW_NONEXISTENT",
		AdminAuth: true,
		Code:      http.StatusNotFound,
		BodyMatchFunc: func(resp []byte) bool {
			var errResp map[string]string
			err := json.Unmarshal(resp, &errResp)
			assert.NoError(t, err)
			assert.Equal(t, "environment variable not found", errResp["error"])
			return true
		},
	})
}

func TestEnvHandler_SensitiveEnvVarRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "super-secret-value"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env?env=TYK_GW_SECRET",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var envResp map[string]interface{}
			err := json.Unmarshal(resp, &envResp)
			assert.NoError(t, err)

			// Verify env var is marked as obfuscated
			assert.Equal(t, true, envResp["obfuscated"])
			// Value should NOT be the actual secret
			assert.NotEqual(t, "super-secret-value", envResp["value"])
			return true
		},
	})
}

func TestConfigHandler_StoragePasswordRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.Storage.Password = "redis-password"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=storage.password",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify field is marked as obfuscated
			assert.Equal(t, true, fieldResp["obfuscated"])
			// Value should NOT be the actual password
			assert.NotEqual(t, "redis-password", fieldResp["value"])
			return true
		},
	})
}

func TestInitConfigViewer(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	// Test that initConfigViewer returns a valid viewer
	viewer, err := ts.Gw.initConfigViewer()
	assert.NoError(t, err)
	assert.NotNil(t, viewer)
}

func TestConfigHandler_NestedField(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.Storage.Database = 5
	})
	defer ts.Close()

	// Test nested non-sensitive field (using database which doesn't affect connectivity)
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=storage.database",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			assert.Equal(t, "storage.database", fieldResp["config_field"])
			assert.Equal(t, "5", fieldResp["value"])
			assert.Equal(t, false, fieldResp["obfuscated"])
			return true
		},
	})
}

func TestConfigHandler_NodeSecretRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.NodeSecret = "node-secret-value"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=node_secret",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify field is marked as obfuscated
			assert.Equal(t, true, fieldResp["obfuscated"])
			// Value should NOT be the actual node secret
			assert.NotEqual(t, "node-secret-value", fieldResp["value"])
			return true
		},
	})
}

func TestEnvHandler_StoragePasswordRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.Storage.Password = "redis-password"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env?env=TYK_GW_STORAGE_PASSWORD",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var envResp map[string]interface{}
			err := json.Unmarshal(resp, &envResp)
			assert.NoError(t, err)

			// Verify env var is marked as obfuscated
			assert.Equal(t, true, envResp["obfuscated"])
			// Value should NOT be the actual password
			assert.NotEqual(t, "redis-password", envResp["value"])
			return true
		},
	})
}

func TestConfigHandler_DBConnectionStringRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.DBAppConfOptions.ConnectionString = "http://dashboard:3000"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=db_app_conf_options.connection_string",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify field is marked as obfuscated
			assert.Equal(t, true, fieldResp["obfuscated"])
			// Value should NOT be the actual connection string
			assert.NotEqual(t, "http://dashboard:3000", fieldResp["value"])
			return true
		},
	})
}

func TestConfigHandler_PolicyConnectionStringRedacted(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
		cnf.Policies.PolicyConnectionString = "http://policy-server:3000"
	})
	defer ts.Close()

	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config?field=policies.policy_connection_string",
		AdminAuth: true,
		Code:      http.StatusOK,
		BodyMatchFunc: func(resp []byte) bool {
			var fieldResp map[string]interface{}
			err := json.Unmarshal(resp, &fieldResp)
			assert.NoError(t, err)

			// Verify field is marked as obfuscated
			assert.Equal(t, true, fieldResp["obfuscated"])
			// Value should NOT be the actual connection string
			assert.NotEqual(t, "http://policy-server:3000", fieldResp["value"])
			return true
		},
	})
}

func TestConfigHandler_ViewerInitError(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	// Override the factory to return an error
	originalFactory := configViewerFactory
	configViewerFactory = func(_ *Gateway) (*structviewer.Viewer, error) {
		return nil, errors.New("simulated viewer initialization error")
	}
	defer func() {
		configViewerFactory = originalFactory
	}()

	// /config should return 500 when viewer initialization fails
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/config",
		AdminAuth: true,
		Code:      http.StatusInternalServerError,
		BodyMatchFunc: func(resp []byte) bool {
			var errResp map[string]interface{}
			err := json.Unmarshal(resp, &errResp)
			assert.NoError(t, err)
			assert.Equal(t, "error", errResp["status"])
			assert.Equal(t, "Failed to initialize config viewer", errResp["message"])
			return true
		},
	})
}

func TestEnvHandler_ViewerInitError(t *testing.T) {
	ts := StartTest(func(cnf *config.Config) {
		cnf.EnableConfigInspection = true
		cnf.Secret = "test-secret"
	})
	defer ts.Close()

	// Override the factory to return an error
	originalFactory := configViewerFactory
	configViewerFactory = func(_ *Gateway) (*structviewer.Viewer, error) {
		return nil, errors.New("simulated viewer initialization error")
	}
	defer func() {
		configViewerFactory = originalFactory
	}()

	// /env should return 500 when viewer initialization fails
	_, _ = ts.Run(t, test.TestCase{
		Method:    http.MethodGet,
		Path:      "/env",
		AdminAuth: true,
		Code:      http.StatusInternalServerError,
		BodyMatchFunc: func(resp []byte) bool {
			var errResp map[string]interface{}
			err := json.Unmarshal(resp, &errResp)
			assert.NoError(t, err)
			assert.Equal(t, "error", errResp["status"])
			assert.Equal(t, "Failed to initialize config viewer", errResp["message"])
			return true
		},
	})
}
