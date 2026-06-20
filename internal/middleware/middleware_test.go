package middleware

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-045
// SW-REQ-045:nominal:nominal
// SW-REQ-045:boundary:nominal
// SW-REQ-045:boundary:boundary
func TestEnabled(t *testing.T) {
	tests := []struct {
		name string
		mws  []apidef.MiddlewareDefinition
		want bool
	}{
		{
			name: "empty definitions",
			mws:  nil,
			want: false,
		},
		{
			name: "named disabled definition",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "mwFunc",
					Path:     "path",
				},
			},
			want: false,
		},
		{
			name: "enabled flag with empty name",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
				},
			},
			want: false,
		},
		{
			name: "only unnamed and disabled definitions",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
				},
				{
					Disabled: true,
					Name:     "mwFunc",
				},
			},
			want: false,
		},
		{
			name: "named enabled definition",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
					Name:     "mwFunc",
				},
			},
			want: true,
		},
		{
			name: "mixed definitions with one enabled",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "mwDisabled",
				},
				{
					Disabled: false,
				},
				{
					Disabled: false,
					Name:     "mwEnabled",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Enabled(tt.mws...); got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
