package errors

import (
	"errors"
	"strings"
)

var (
	// SW-REQ-040
	New            = errors.New
	Is             = errors.Is
	As             = errors.As
	Join           = errors.Join
	Unwrap         = errors.Unwrap
	ErrUnsupported = errors.ErrUnsupported
)

// SW-REQ-040
func Formatter(errs []error) string {
	var result strings.Builder
	for i, err := range errs {
		result.WriteString(err.Error())
		if i < len(errs)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}
