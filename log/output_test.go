package log

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeOutput(t *testing.T) {
	tests := []struct {
		name        string
		output      Output
		expected    interface{}
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
