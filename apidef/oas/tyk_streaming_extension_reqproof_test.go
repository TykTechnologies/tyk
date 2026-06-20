package oas

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-057
// SW-REQ-057:nominal:nominal
// SW-REQ-057:boundary:nominal
// SW-REQ-057:determinism:nominal
func TestXTykStreamingPreservesExtensionShape(t *testing.T) {
	t.Run("nil and empty streams keep explicit streams field", func(t *testing.T) {
		nilPayload, err := json.Marshal(XTykStreaming{})
		require.NoError(t, err)
		assert.JSONEq(t, `{"streams":null}`, string(nilPayload))

		emptyPayload, err := json.Marshal(XTykStreaming{Streams: map[string]interface{}{}})
		require.NoError(t, err)
		assert.JSONEq(t, `{"streams":{}}`, string(emptyPayload))
	})

	t.Run("populated streams preserve nested configuration data across JSON round trip", func(t *testing.T) {
		original := XTykStreaming{
			Streams: map[string]interface{}{
				"orders": map[string]interface{}{
					"input":   "kafka",
					"output":  "http",
					"enabled": true,
				},
			},
		}

		payload, err := json.Marshal(original)
		require.NoError(t, err)
		assert.JSONEq(t, `{"streams":{"orders":{"input":"kafka","output":"http","enabled":true}}}`, string(payload))

		var decoded XTykStreaming
		require.NoError(t, json.Unmarshal(payload, &decoded))

		require.Contains(t, decoded.Streams, "orders")
		orders, ok := decoded.Streams["orders"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "kafka", orders["input"])
		assert.Equal(t, "http", orders["output"])
		assert.Equal(t, true, orders["enabled"])
	})
}
