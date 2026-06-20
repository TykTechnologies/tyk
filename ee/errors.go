package ee

import (
	"errors"
)

var (
	// SW-REQ-113
	ErrActionNotAllowed = errors.New("action not allowed")
)
