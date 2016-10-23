package jwt

import (
	"errors"
)

// Error constants
var (
	ErrInvalidKey       = errors.New("key is invalid or of invalid type")
	ErrHashUnavailable  = errors.New("the requested hash function is unavailable")
	ErrNoTokenInRequest = errors.New("no token present in request")
)

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed
	ValidationErrorExpired                             // Exp validation failed
	ValidationErrorNotValidYet                         // NBF validation failed
)

// Helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		Inner:  errors.New(errorText),
		Errors: errorFlags,
	}
}

// The error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.Inner == nil {
		return "token is invalid"
	}
	return e.Inner.Error()
}

// No errors
func (e *ValidationError) valid() bool {
	if e.Errors > 0 {
		return false
	}
	return true
}
