package certusage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type reqproofTracker struct {
	required map[string]bool
	apis     map[string][]string
}

func (t reqproofTracker) Required(certID string) bool {
	return t.required[certID]
}

func (t reqproofTracker) APIs(certID string) []string {
	return t.apis[certID]
}

var _ Tracker = reqproofTracker{}

// Verifies: STK-REQ-043, SYS-REQ-131, SW-REQ-118
// MCDC SYS-REQ-131: certificate_usage_tracker_contract_available=T => TRUE
// SW-REQ-118:nominal:nominal
// SW-REQ-118:boundary:nominal
// SW-REQ-118:determinism:nominal
//
//mcdc:ignore SYS-REQ-131: certificate_usage_tracker_contract_available=F => FALSE -- the onboarded certificate usage tracker operation is a local Go interface contract that is either compile-time available with the Required and APIs method signatures or the package fails to compile; a runtime unavailable contract state is not reachable for these APIs [reviewed: human:buger]
func TestTrackerInterfaceContractPreservesLocalLookupShape(t *testing.T) {
	tracker := Tracker(reqproofTracker{
		required: map[string]bool{
			"used-cert": true,
		},
		apis: map[string][]string{
			"used-cert": []string{"api-one", "api-two"},
		},
	})

	tests := []struct {
		name         string
		certID       string
		wantRequired bool
		wantAPIs     []string
	}{
		{name: "used certificate", certID: "used-cert", wantRequired: true, wantAPIs: []string{"api-one", "api-two"}},
		{name: "unused certificate", certID: "unused-cert", wantRequired: false, wantAPIs: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantRequired, tracker.Required(tt.certID))
			assert.Equal(t, tt.wantAPIs, tracker.APIs(tt.certID))
		})
	}
}
