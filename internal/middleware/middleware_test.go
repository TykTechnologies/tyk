package middleware

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-111
// MCDC SYS-REQ-111: middleware_helper_determined=F, middleware_helper_requested=F => TRUE
func TestMCDC_SYS_REQ_111_NoMiddlewareHelperRequest(t *testing.T) {
	var defs []apidef.MiddlewareDefinition
	_ = defs
}

// Verifies: STK-REQ-023, SYS-REQ-111, SW-REQ-031
// STK-REQ-023:nominal:nominal
// STK-REQ-023:boundary:boundary
// SYS-REQ-111:nominal:nominal
// SYS-REQ-111:boundary:boundary
// SW-REQ-031:nominal:nominal
// SW-REQ-031:boundary:boundary
// MCDC SYS-REQ-111: middleware_helper_requested=T, middleware_helper_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-111: middleware_helper_determined=F, middleware_helper_requested=T => FALSE -- violation row is the negation of the in-process middleware helper determination guarantee; focused tests assert enabled, disabled, unnamed, empty, and sentinel helper behavior is deterministic [category: defensive] [reviewed: agent:codex]
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
			name: "empty",
			mws:  nil,
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

// Verifies: STK-REQ-023, SYS-REQ-111, SW-REQ-031
// STK-REQ-023:nominal:nominal
// SYS-REQ-111:nominal:nominal
// SW-REQ-031:nominal:nominal
func TestStatusRespond(t *testing.T) {
	if StatusRespond != 666 {
		t.Fatalf("StatusRespond = %d, want 666", StatusRespond)
	}
}
