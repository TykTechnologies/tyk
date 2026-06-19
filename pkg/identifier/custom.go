package identifier

import (
	"regexp"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

var (
	// SW-REQ-022
	validPolicyRe            = regexp.MustCompile(`^[a-zA-Z0-9.\-_~]+$`)
	ErrInvalidCustomPolicyId = errpack.Domain("Invalid Policy ID: Allowed characters: a-z, A-Z, 0-9, ., _, -, ~")
)

// CustomPolicyId (user-defined-identifier)
// SW-REQ-022
type CustomPolicyId string

// SW-REQ-022
func (c CustomPolicyId) String() string {
	return string(c)
}

// SW-REQ-022
func (c CustomPolicyId) Validate() error {
	if len(c) == 0 {
		return nil
	}

	if !validPolicyRe.MatchString(string(c)) {
		return ErrInvalidCustomPolicyId
	}

	return nil
}
