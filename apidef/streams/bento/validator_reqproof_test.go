package bento

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-095
// SW-REQ-095:nominal:nominal
// SW-REQ-095:boundary:nominal
// SW-REQ-095:error_handling:negative
// SW-REQ-095:determinism:nominal
func TestBentoConfigValidatorPreservesSupportBehavior(t *testing.T) {
	validKafkaDocument := []byte(`{
		"input": {
			"kafka": {
				"addresses": [],
				"topics": [],
				"target_version": "2.1.0",
				"consumer_group": "",
				"checkpoint_limit": 1024,
				"auto_replay_nacks": true
			}
		}
	}`)

	t.Run("schema loading is idempotent and exposes default schema bytes", func(t *testing.T) {
		require.NoError(t, loadBentoSchemas())
		first := append([]byte(nil), bentoSchemas[DefaultValidator]...)
		require.NotEmpty(t, first)
		t.Cleanup(func() {
			bentoSchemas[DefaultValidator] = first
		})

		bentoSchemas[DefaultValidator] = []byte(`mutated`)
		require.NoError(t, loadBentoSchemas())
		assert.Equal(t, []byte(`mutated`), bentoSchemas[DefaultValidator])
	})

	t.Run("default constructor wires embedded schema loader", func(t *testing.T) {
		validator, err := NewDefaultConfigValidator()
		require.NoError(t, err)
		require.NotNil(t, validator)
		require.NotNil(t, validator.schemaLoader)

		assert.NoError(t, validator.Validate(validKafkaDocument))
	})

	t.Run("default validator reports schema validation errors with field paths", func(t *testing.T) {
		validator, err := NewDefaultConfigValidator()
		require.NoError(t, err)

		invalidDocument := []byte(`{
			"input": {
				"kafka": {
					"addresses": "not-a-list",
					"topics": "not-a-list",
					"target_version": "2.1.0",
					"consumer_group": "",
					"checkpoint_limit": 1024,
					"auto_replay_nacks": "not-a-bool"
				}
			}
		}`)

		err = validator.Validate(invalidDocument)
		require.Error(t, err)
		message := err.Error()
		assert.Contains(t, message, "input.kafka.addresses")
		assert.Contains(t, message, "input.kafka.topics")
		assert.Contains(t, message, "input.kafka.auto_replay_nacks")
		assert.GreaterOrEqual(t, strings.Count(message, "\n"), 2)
	})

	t.Run("default validator propagates malformed document loader errors", func(t *testing.T) {
		validator, err := NewDefaultConfigValidator()
		require.NoError(t, err)

		err = validator.Validate([]byte(`{"input":`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected EOF")
	})

	t.Run("experimental validator deliberately accepts valid invalid and malformed inputs", func(t *testing.T) {
		validator := NewEnableAllExperimentalConfigValidator()
		require.NotNil(t, validator)

		tests := []struct {
			name     string
			document []byte
		}{
			{
				name:     "valid default document",
				document: validKafkaDocument,
			},
			{
				name:     "schema-invalid document",
				document: []byte(`{"input":{"kafka":{"auto_replay_nacks":"not-a-bool"}}}`),
			},
			{
				name:     "malformed document",
				document: []byte(`{"input":`),
			},
			{
				name:     "nil document",
				document: nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.NoError(t, validator.Validate(tt.document))
			})
		}
	})
}
