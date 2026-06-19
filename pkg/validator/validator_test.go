package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: SW-REQ-034
// SW-REQ-034:error_handling:negative
func TestValidatorRegistrationFailsFast(t *testing.T) {
	validator := New().(*validatorImpl)

	assert.Panics(t, func() {
		validator.mustRegisterValidator("", skipValidator)
	})
}
