package openid

import (
	"net/http"
	"strings"
)

// GetIdTokenFunc represents the function used to provide the OIDC idToken.
// It uses the provided request(r) to return the id token string(token).
// If the token was not found or had a bad format this function will return an error.
type GetIDTokenFunc func(r *http.Request) (token string, err error)

// GetIdTokenAuthorizationHeader is the default implementation of the GetIdTokenFunc
// used by this package.I looks for the idToken in the http Authorization header with
// the format 'Bearer TokenString'. If found it will return 'TokenString' if not found
// or the format does not match it will return an error.
func getIDTokenAuthorizationHeader(r *http.Request) (t string, err error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderNotFound, Message: "The 'Authorization' header was not found or was empty.", HTTPStatus: http.StatusBadRequest}
	}

	p := strings.Split(h, " ")

	if len(p) != 2 {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderWrongFormat, Message: "The 'Authorization' header did not have the correct format.", HTTPStatus: http.StatusBadRequest}
	}

	if p[0] != "Bearer" {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderWrongSchemeName, Message: "The 'Authorization' header scheme name was not 'Bearer'", HTTPStatus: http.StatusBadRequest}
	}

	return p[1], nil
}
