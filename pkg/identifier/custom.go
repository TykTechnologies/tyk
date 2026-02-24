package identifier

import (
	"regexp"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

var (
	validRe            = regexp.MustCompile(`^[a-zA-Z0-9.\-_~]+$`)
	ErrInvalidCustomId = errpack.Domain("Invalid custom ID: Allowed characters: a-z, A-Z, 0-9, ., _, -, ~")
)

// Custom (user-defined-identifier)
type Custom string

func (c Custom) String() string {
	return string(c)
}

func (c Custom) Validate() error {
	if len(c) == 0 {
		return nil
	}

	if !validRe.MatchString(string(c)) {
		return ErrInvalidCustomId
	}

	return nil
}
