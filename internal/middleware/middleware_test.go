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
			name: "empty name and path",
			mws: []apidef.MiddlewareDefinition{
				{},
			},
			want: false,
		},
		{
			name: "enabled",
			mws: []apidef.MiddlewareDefinition{
				{
					Name: "mwFunc",
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
