package pkg

import (
	"fmt"
	"os"
	"testing"
)

func TestSetGODebugEnv(t *testing.T) {
	tests := []struct {
		name     string
		initial  string
		expected string
	}{
		{
			name:     "empty GODEBUG",
			initial:  "",
			expected: disableIgnoreCNDebugVal,
		},
		{
			name:     "non empty GODEBUG",
			initial:  "gctrace=1",
			expected: fmt.Sprintf("gctrace=1,%s", disableIgnoreCNDebugVal),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				os.Setenv(goDebugEnvKey, "")
			}()
			os.Setenv(goDebugEnvKey, tt.initial)
			SetGODebugEnv()
		})
	}
}
