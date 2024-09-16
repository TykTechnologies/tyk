package errors

import (
	"errors"
	"fmt"
	"strings"
)

var (
	New            = errors.New
	Is             = errors.Is
	Join           = errors.Join
	Unwrap         = errors.Unwrap
	ErrUnsupported = errors.ErrUnsupported
)

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

func Wrap(err error, message string) error {
	if err == nil {
		return err
	}
	return fmt.Errorf("%s: %w", message, err)
}
