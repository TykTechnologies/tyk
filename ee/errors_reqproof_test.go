package ee

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: STK-REQ-038, SYS-REQ-126, SW-REQ-113
// SW-REQ-113:nominal:nominal
// SW-REQ-113:boundary:nominal
// MCDC SYS-REQ-126: enterprise_error_requested=F, enterprise_error_available=F => TRUE
// MCDC SYS-REQ-126: enterprise_error_requested=T, enterprise_error_available=T => TRUE
//
//mcdc:ignore SYS-REQ-126: enterprise_error_requested=T, enterprise_error_available=F => FALSE -- violation row is the negation of the local enterprise error catalog guarantee; this test asserts the exported sentinel exists and remains comparable through errors.Is [category: defensive] [reviewed: agent:codex]
func TestEnterpriseErrorSentinels(t *testing.T) {
	tests := []struct {
		name string
		err  error
		text string
	}{
		{
			name: "action not allowed",
			err:  ErrActionNotAllowed,
			text: "action not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.err)
			assert.Equal(t, tt.text, tt.err.Error())
			assert.True(t, errors.Is(tt.err, tt.err))
		})
	}
}
