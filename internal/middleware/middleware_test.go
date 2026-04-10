package middleware

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestEnabled(t *testing.T) {
	tests := []struct {
		name string
		mws  []apidef.MiddlewareDefinition
		want bool
	}{
		{
			name: "disabled",
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
			name: "enabled with empty name and path",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
				},
			},
			want: false,
		},
		{
			name: "enabled with empty name and path",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
				},
			},
			want: false,
		},
		{
			name: "enabled",
			mws: []apidef.MiddlewareDefinition{
				{
					Disabled: false,
					Name:     "mwFunc",
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
