package identifier

import (
	"regexp"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

// validCustomIdRe holds the characters allowed in any user-defined identifier.
var validCustomIdRe = regexp.MustCompile(`^[a-zA-Z0-9.\-_~]+$`)

// alphanumericRe matches any letter or digit. API IDs made only of punctuation
// (e.g. "." or "..") are dot-segments in a URL path and cannot be addressed.
var alphanumericRe = regexp.MustCompile(`[a-zA-Z0-9]`)

var (
	ErrInvalidCustomPolicyId = errpack.Domain("Invalid Policy ID: Allowed characters: a-z, A-Z, 0-9, ., _, -, ~")
	ErrInvalidCustomApiId    = errpack.Domain("Invalid API ID: Allowed characters: a-z, A-Z, 0-9, ., _, -, ~ and must contain at least one letter or digit")
)

// validateCustomId returns invalidErr when id contains characters outside the
// allowed set. An empty id is valid: it means the identifier is generated
// rather than user-defined.
func validateCustomId(id string, invalidErr error) error {
	if len(id) == 0 {
		return nil
	}

	if !validCustomIdRe.MatchString(id) {
		return invalidErr
	}

	return nil
}

// CustomPolicyId (user-defined-identifier)
type CustomPolicyId string

func (c CustomPolicyId) String() string {
	return string(c)
}

func (c CustomPolicyId) Validate() error {
	return validateCustomId(string(c), ErrInvalidCustomPolicyId)
}

// CustomApiId (user-defined-identifier)
type CustomApiId string

func (c CustomApiId) String() string {
	return string(c)
}

func (c CustomApiId) Validate() error {
	if err := validateCustomId(string(c), ErrInvalidCustomApiId); err != nil {
		return err
	}

	if len(c) > 0 && !alphanumericRe.MatchString(string(c)) {
		return ErrInvalidCustomApiId
	}

	return nil
}
