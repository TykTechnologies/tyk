package log

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLevel_Parse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		stored   Level
	}{
		{"error_lowercase", "error", true, "error"},
		{"info_uppercase", "INFO", true, "info"},
		{"invalid_level", "invalid", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l Level
			ok := l.Parse(tt.input)
			assert.Equal(t, tt.expected, ok)
			assert.Equal(t, tt.stored, l)
		})
	}
}

func TestLevel_LogrusLevel(t *testing.T) {
	tests := []struct {
		name          string
		level         Level
		expectedLevel logrus.Level
		expectedOk    bool
	}{
		{"valid_error", Level("error"), logrus.ErrorLevel, true},
		{"valid_mixed_case", Level("WaRn"), logrus.WarnLevel, true},
		{"invalid", Level("unknown"), 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lvl, ok := tt.level.LogrusLevel()
			assert.Equal(t, tt.expectedOk, ok)
			if tt.expectedOk {
				assert.Equal(t, tt.expectedLevel, lvl)
			}
		})
	}
}
