package bento

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateBentoConfiguration(t *testing.T) {
	validator, err := NewDefaultConfigValidator()
	require.NoError(t, err)

	t.Run("Valid Bento Configuration", func(t *testing.T) {
		validDocument := []byte(`{
    "input": {
        "label": "",
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
		err = validator.Validate(validDocument)
		require.NoError(t, err)
	})

	t.Run("Invalid Bento Configuration", func(t *testing.T) {
		invalidDocument := []byte(`{
    "input": {
        "label": "",
        "kafka": {
            "addresses": [],
            "topics": [],
            "target_version": "2.1.0",
            "consumer_group": "",
            "checkpoint_limit": 1024,
            "auto_replay_nacks": "some-string"
        }
    }
}`)

		err = validator.Validate(invalidDocument)
		require.ErrorContains(t, err, "input.kafka.auto_replay_nacks: Invalid type. Expected: boolean, given: string")
	})

	t.Run("Allow Additional Properties", func(t *testing.T) {
		validDocumentWithAdditionalProperties := []byte(`{
    "input": {
        "label": "",
        "kafka": {
            "addresses": [],
            "topics": [],
            "target_version": "2.1.0",
            "consumer_group": "",
            "checkpoint_limit": 1024,
            "auto_replay_nacks": true
        },
        "additional": {
            "configuration": true
        }
    },
    "output": {
        "label": "",
        "drop_on": {
            "error": false,
            "error_patterns": [],
            "back_pressure": "30s",
            "output": null
        },
        "aws_sns": {
            "topic_arn": "",
            "message_group_id": "",
            "message_deduplication_id": "",
            "max_in_flight": 64,
            "metadata": {
                "exclude_prefixes": []
            }
        }
    }
}`)
		err = validator.Validate(validDocumentWithAdditionalProperties)
		require.NoError(t, err)
	})
}
