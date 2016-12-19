package openid

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// SetupErrorCode is the type of error code that can
// be returned by the operations done during middleware setup.
type SetupErrorCode uint32

// Setup error constants.
const (
	SetupErrorInvalidIssuer           SetupErrorCode = iota // Invalid issuer provided during setup.
	SetupErrorInvalidClientIDs                              // Invalid client id collection provided during setup.
	SetupErrorEmptyProviderCollection                       // Empty collection of providers provided during setup.
)

// ValidationErrorCode is the type of error code that can
// be returned by the operations done during token validation.
type ValidationErrorCode uint32

// Validation error constants.
const (
	ValidationErrorAuthorizationHeaderNotFound        ValidationErrorCode = iota // Authorization header not found on request.
	ValidationErrorAuthorizationHeaderWrongFormat                                // Authorization header unexpected format.
	ValidationErrorAuthorizationHeaderWrongSchemeName                            // Authorization header unexpected scheme.
	ValidationErrorJwtValidationFailure                                          // Jwt token validation failed with a known error.
	ValidationErrorJwtValidationUnknownFailure                                   // Jwt token validation failed with an unknown error.
	ValidationErrorInvalidAudienceType                                           // Unexpected token audience type.
	ValidationErrorInvalidAudience                                               // Unexpected token audience content.
	ValidationErrorAudienceNotFound                                              // Unexpected token audience value. Audience not registered.
	ValidationErrorInvalidIssuerType                                             // Unexpected token issuer type.
	ValidationErrorInvalidIssuer                                                 // Unexpected token issuer content.
	ValidationErrorIssuerNotFound                                                // Unexpected token value. Issuer not registered.
	ValidationErrorGetOpenIdConfigurationFailure                                 // Failure while retrieving the OIDC configuration.
	ValidationErrorDecodeOpenIdConfigurationFailure                              // Failure while decoding the OIDC configuration.
	ValidationErrorGetJwksFailure                                                // Failure while retrieving jwk set.
	ValidationErrorDecodeJwksFailure                                             // Failure while decoding the jwk set.
	ValidationErrorEmptyJwk                                                      // Empty jwk returned.
	ValidationErrorEmptyJwkKey                                                   // Empty jwk key set returned.
	ValidationErrorMarshallingKey                                                // Error while marshalling the signing key.
	ValidationErrorKidNotFound                                                   // Key identifier not found.
	ValidationErrorInvalidSubjectType                                            // Unexpected token subject type.
	ValidationErrorInvalidSubject                                                // Unexpected token subject content.
	ValidationErrorSubjectNotFound                                               // Token missing the 'sub' claim.
	ValidationErrorIdTokenEmpty                                                  // Empty ID token.
	ValidationErrorEmptyProviders                                                // Empty collection of providers.
)

const setupErrorMessagePrefix string = "Setup Error."
const validationErrorMessagePrefix string = "Validation Error."

// SetupError represents the error returned by operations called during
// middleware setup.
type SetupError struct {
	Err     error
	Code    SetupErrorCode
	Message string
}

// Error returns a formatted string containing the error Message.
func (se SetupError) Error() string {
	return fmt.Sprintf("Setup error. %v", se.Message)
}

// ValidationError represents the error returned by operations called during
// token validation.
type ValidationError struct {
	Err        error
	Code       ValidationErrorCode
	Message    string
	HTTPStatus int
}

// The ErrorHandlerFunc represents the function used to handle errors during token
// validation. Applications can have their own implementation of this function and
// register it using the ErrorHandler option. Through this extension point applications
// can choose what to do upon different error types, for instance return an certain HTTP Status code
// and/or include some detailed message in the response.
// This function returns false if the next handler registered after the ID Token validation
// should be executed when an error is found or true if the execution should be stopped.
type ErrorHandlerFunc func(error, http.ResponseWriter, *http.Request) bool

// Error returns a formatted string containing the error Message.
func (ve ValidationError) Error() string {
	return fmt.Sprintf("Validation error. %v", ve.Message)
}

// jwtErrorToOpenIdError converts errors of the type *jwt.ValidationError returned during token validation into errors of type *ValidationError
func jwtErrorToOpenIdError(e error) *ValidationError {
	if jwtError, ok := e.(*jwt.ValidationError); ok {
		if (jwtError.Errors & (jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired | jwt.ValidationErrorSignatureInvalid)) != 0 {
			return &ValidationError{Code: ValidationErrorJwtValidationFailure, Message: "Jwt token validation failed.", HTTPStatus: http.StatusUnauthorized}
		}

		if (jwtError.Errors & jwt.ValidationErrorMalformed) != 0 {
			return &ValidationError{Code: ValidationErrorJwtValidationFailure, Message: "Jwt token validation failed.", HTTPStatus: http.StatusBadRequest}
		}

		if (jwtError.Errors & jwt.ValidationErrorUnverifiable) != 0 {
			// TODO: improve this once https://github.com/dgrijalva/jwt-go/issues/108 is resolved.
			// Currently jwt.Parse does not surface errors returned by the KeyFunc.
			return &ValidationError{Code: ValidationErrorJwtValidationFailure, Message: jwtError.Error(), HTTPStatus: http.StatusUnauthorized}
		}
	}

	return &ValidationError{Code: ValidationErrorJwtValidationUnknownFailure, Message: "Jwt token validation failed with unknown error.", HTTPStatus: http.StatusInternalServerError}
}

func validationErrorToHTTPStatus(e error, rw http.ResponseWriter, req *http.Request) (halt bool) {
	if verr, ok := e.(*ValidationError); ok {
		http.Error(rw, verr.Message, verr.HTTPStatus)
	} else {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(rw, e.Error())
	}

	return true
}
