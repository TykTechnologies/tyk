package errors

import (
	"strings"
)

// Join concatenates multiple errors into a single error.
// Returns nil if no errors are passed or if all errors are nil.
func Join(errs ...error) error {
	var nonNilErrors []string

	for _, err := range errs {
		if err != nil {
			nonNilErrors = append(nonNilErrors, err.Error())
		}
	}

	if len(nonNilErrors) == 0 {
		return nil
	}

	// Join the non-nil error messages into a single string separated by "; "
	return &joinedError{strings.Join(nonNilErrors, "; ")}
}

// joinedError is a custom error type to hold the joined error message.
type joinedError struct {
	msg string
}

func (e *joinedError) Error() string {
	return e.msg
}
