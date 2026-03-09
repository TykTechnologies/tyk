package identifier

import (
	"regexp"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

var (
	validPolicyRe            = regexp.MustCompile(`^[a-zA-Z0-9.\-_~]+$`)
	ErrInvalidCustomPolicyId = errpack.Domain("Invalid Policy id ID: Allowed characters: a-z, A-Z, 0-9, ., _, -, ~")
)

// CustomPolicyId (user-defined-identifier)
type CustomPolicyId string

func (c CustomPolicyId) String() string {
	return string(c)
}

func (c CustomPolicyId) Validate() error {
	if len(c) == 0 {
		return nil
	}

	if !validPolicyRe.MatchString(string(c)) {
		return ErrInvalidCustomPolicyId
	}

	return nil
}
