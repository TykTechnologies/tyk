package streams

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestStreamStart(t *testing.T) {
	str := NewStream(nil)
	require.NotNil(t, str)

	t.Run("success", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_path": "/subscribe",
				},
			},
		}, nil)
		require.NoError(t, err)
	})

	t.Run("fail due to bad schema", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_pat": "/subscribe",
				},
			},
		}, nil)
		require.Error(t, err)
	})
}

func TestStreamStop(t *testing.T) {
	validConfig := map[string]interface{}{
		"input": map[string]interface{}{
			"http_server": map[string]interface{}{
				"path": "/post",
			},
		},
		"output": map[string]interface{}{
			"http_server": map[string]interface{}{
				"ws_path": "/subscribe",
			},
		},
	}
	t.Run("successfully stop", func(t *testing.T) {
		str := NewStream(nil)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		err = str.Stop()
		require.NoError(t, err)
	})

	t.Run("no error stopping cause no stream", func(t *testing.T) {
		str := NewStream(nil)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		str.stream = nil
		require.NoError(t, str.Stop())
	})
}

func TestRemoveAndWhitelistUnsafeComponents(t *testing.T) {
	t.Run("Remove Unsafe Components", func(t *testing.T) {
		stream := NewStream(nil)
		unsafeConfig := map[string]interface{}{
			"input": map[string]interface{}{
				"type": "file",
				"file": map[string]interface{}{
					"paths": []string{"test.txt"},
				},
			},
			"output": map[string]interface{}{
				"type": "socket",
				"socket": map[string]interface{}{
					"network": "tcp",
					"address": "localhost:1234",
				},
			},
		}

		configPayload, err := yaml.Marshal(unsafeConfig)
		if err != nil {
			t.Fatalf("Failed to marshal unsafe config: %v", err)
		}

		sanitizedConfig := stream.removeUnsafe(configPayload)
		if containsUnsafeComponent(sanitizedConfig) {
			t.Fatalf("Unsafe components were not removed: \n%s", string(sanitizedConfig))
		}
	})

	t.Run("Whitelist Components", func(t *testing.T) {
		stream := NewStream([]string{"file", "socket"})

		unsafeConfig := map[string]interface{}{
			"input": map[string]interface{}{
				"file": map[string]interface{}{
					"paths": []string{"test.txt"},
				},
			},
			"output": map[string]interface{}{
				"socket": map[string]interface{}{
					"network": "tcp",
					"address": "localhost:1234",
				},
			},
		}

		configPayload, err := yaml.Marshal(unsafeConfig)
		if err != nil {
			t.Fatalf("Failed to marshal unsafe config: %v", err)
		}

		sanitizedConfig := stream.removeUnsafe(configPayload)
		if !containsUnsafeComponent(sanitizedConfig) {
			t.Fatalf("Whitelisted components were removed: \n%s", string(sanitizedConfig))
		}
	})
}

// Helper function to check if the config contains any unsafe component
func containsUnsafeComponent(configPayload []byte) bool {
	yamlString := string(configPayload)
	for _, key := range unsafeComponents {
		if strings.Contains(yamlString, key+":") {
			return true
		}
	}
	return false
}
