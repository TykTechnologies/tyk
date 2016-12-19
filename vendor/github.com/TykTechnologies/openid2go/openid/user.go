package openid

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// User represents the authenticated user encapsulating information obtained from the validated ID token.
//
// The Issuer contains the value from the 'iss' claim found in the ID Token.
//
// The ID contains the value of the 'sub' claim found in the ID Token.
//
// The Claims contains all the claims present found in the ID Token
type User struct {
	Issuer string
	ID     string
	Claims map[string]interface{}
}

func newUser(t *jwt.Token) (*User, error) {
	if t == nil {
		return nil, &ValidationError{Code: ValidationErrorIdTokenEmpty, Message: "The token provided to created a user was nil.", HTTPStatus: http.StatusUnauthorized}
	}

	iss := getIssuer(t).(string)

	if iss == "" {
		return nil, &ValidationError{Code: ValidationErrorInvalidIssuer, Message: "The token provided to created a user did not contain a valid 'iss' claim", HTTPStatus: http.StatusInternalServerError}
	}

	sub := getSubject(t).(string)

	if sub == "" {
		return nil, &ValidationError{Code: ValidationErrorInvalidSubject, Message: "The token provided to created a user did not contain a valid 'sub' claim.", HTTPStatus: http.StatusInternalServerError}

	}

	u := new(User)
	u.Issuer = iss
	u.ID = sub
	u.Claims = t.Claims.(jwt.MapClaims)
	return u, nil
}
