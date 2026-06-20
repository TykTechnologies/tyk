package streams

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// Verifies: STK-REQ-039, SYS-REQ-127, SW-REQ-114
// STK-REQ-039:STK-REQ-039-AC-03:acceptance
// SW-REQ-114:nominal:nominal
// SW-REQ-114:error_handling:negative
func TestStreamStart(t *testing.T) {
	str := NewStream(nil, testLogger())
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

// Verifies: STK-REQ-039, SYS-REQ-127, SW-REQ-114
// STK-REQ-039:STK-REQ-039-AC-03:acceptance
// SW-REQ-114:nominal:nominal
// SW-REQ-114:boundary:nominal
func TestStreamStop(t *testing.T) {
	logger := testLogger()
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
		str := NewStream(nil, logger)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		err = str.Stop()
		require.NoError(t, err)
	})

	t.Run("no error stopping cause no stream", func(t *testing.T) {
		str := NewStream(nil, logger)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		str.stream = nil
		require.NoError(t, str.Stop())
	})
}

// Verifies: STK-REQ-039, SYS-REQ-127, SW-REQ-114
// STK-REQ-039:STK-REQ-039-AC-03:acceptance
// SW-REQ-114:access_denied:nominal
// SW-REQ-114:boundary:nominal
func TestRemoveAndWhitelistUnsafeComponents(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
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

	tests := []struct {
		name          string
		allowUnsafe   []string
		wantUnsafeKey bool
	}{
		{
			name:          "remove unsafe components by default",
			allowUnsafe:   nil,
			wantUnsafeKey: false,
		},
		{
			name:          "preserve whitelisted unsafe components",
			allowUnsafe:   []string{"file", "socket"},
			wantUnsafeKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := NewStream(tt.allowUnsafe, logger)

			configPayload, err := yaml.Marshal(unsafeConfig)
			require.NoError(t, err)

			sanitizedConfig := stream.removeUnsafe(configPayload)
			require.Equal(t, tt.wantUnsafeKey, containsUnsafeComponent(sanitizedConfig), string(sanitizedConfig))
		})
	}
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

func testLogger() *logrus.Entry {
	return logrus.NewEntry(logrus.New())
}
