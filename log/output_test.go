package log

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeOutput(t *testing.T) {
	tests := []struct {
		name        string
		output      Output
		expected    any
		expectError bool
	}{
		{"stdout_success", OutputStdout, os.Stdout, false},
		{"stderr_success", OutputStderr, os.Stderr, false},
		{"unknown_failure", Output("random_unsupported_output"), nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer, err := MakeOutput(tt.output, nil)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, writer)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, writer)
			}
		})
	}
}

func TestMakeOutput_Options(t *testing.T) {
	for _, opts := range []string{"", "null", "{}"} {
		writer, err := MakeOutput(OutputStdout, json.RawMessage(opts))
		assert.NoError(t, err, "options %q", opts)
		assert.Equal(t, os.Stdout, writer)
	}

	writer, err := MakeOutput(OutputStderr, json.RawMessage(`{"path": "/dev/null"}`))
	assert.ErrorContains(t, err, `output "stderr" takes no output_options`)
	assert.Nil(t, writer)
}
