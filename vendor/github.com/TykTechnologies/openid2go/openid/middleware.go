package openid

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// The Configuration contains the entities needed to perform ID token validation.
// This type should be instantiated at the application startup time.
type Configuration struct {
	tokenValidator JWTTokenValidator
	IDTokenGetter  GetIDTokenFunc
	errorHandler   ErrorHandlerFunc
}

type option func(*Configuration) error

// The NewConfiguration creates a new instance of Configuration and returns a pointer to it.
// This function receives a collection of the function type option. Each of those functions are
// responsible for setting some part of the returned *Configuration. If any if the option functions
// returns an error then NewConfiguration will return a nil configuration and that error.
func NewConfiguration(options ...option) (*Configuration, error) {
	m := new(Configuration)
	cp := newHTTPConfigurationProvider(http.Get, jsonDecodeResponse)
	jp := newHTTPJwksProvider(http.Get, jsonDecodeResponse)
	ksp := newSigningKeySetProvider(cp, jp, pemEncodePublicKey)
	kp := newSigningKeyProvider(ksp)
	m.tokenValidator = newIDTokenValidator(nil, jwt.Parse, kp)

	for _, option := range options {
		err := option(m)

		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

// The ProvidersGetter option registers the function responsible for returning the
// providers containing the valid issuer and client IDs used to validate the ID Token.
func ProvidersGetter(pg GetProvidersFunc) func(*Configuration) error {
	return func(c *Configuration) error {
		c.tokenValidator.(*idTokenValidator).provGetter = pg
		return nil
	}
}

func TokenValidator(tv JWTTokenValidator) func(*Configuration) error {
	return func(c *Configuration) error {
		c.tokenValidator = tv
		return nil
	}
}

// The ErrorHandler option registers the function responsible for handling
// the errors returned during token validation. When this option is not used then the
// middleware will use the default internal implementation validationErrorToHTTPStatus.
func ErrorHandler(eh ErrorHandlerFunc) func(*Configuration) error {
	return func(c *Configuration) error {
		c.errorHandler = eh
		return nil
	}
}

// The Authenticate middleware performs the validation of the OIDC ID Token.
// If an error happens, i.e.: expired token, the next handler may or may not executed depending on the
// provided ErrorHandlerFunc option. The default behavior, determined by validationErrorToHTTPStatus,
// stops the execution and returns Unauthorized.
// If the validation is successful then the next handler(h) will be executed.
func Authenticate(conf *Configuration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, halt := authenticate(conf, w, r); !halt {
			h.ServeHTTP(w, r)
		}
	})
}

// The AuthenticateUser middleware performs the validation of the OIDC ID Token and
// forwards the authenticated user's information to the next handler in the pipeline.
// If an error happens, i.e.: expired token, the next handler may or may not executed depending on the
// provided ErrorHandlerFunc option. The default behavior, determined by validationErrorToHTTPStatus,
// stops the execution and returns Unauthorized.
// If the validation is successful then the next handler(h) will be executed and will
// receive the authenticated user information.
func AuthenticateUser(conf *Configuration, h UserHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, halt := authenticateUser(conf, w, r); !halt {
			h.ServeHTTPWithUser(u, w, r)
		}
	})
}

// Exported authenticate so we don't need to use the middleware
func AuthenticateOIDWithUser(c *Configuration, rw http.ResponseWriter, req *http.Request) (*User, *jwt.Token, bool) {
	return authenticateUserWithToken(c, rw, req)
}

func authenticate(c *Configuration, rw http.ResponseWriter, req *http.Request) (t *jwt.Token, halt bool) {
	var tg GetIDTokenFunc
	if c.IDTokenGetter == nil {
		tg = getIDTokenAuthorizationHeader
	} else {
		tg = c.IDTokenGetter
	}

	var eh ErrorHandlerFunc
	if c.errorHandler == nil {
		eh = validationErrorToHTTPStatus
	} else {
		eh = c.errorHandler
	}

	ts, err := tg(req)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	vt, err := c.tokenValidator.Validate(ts)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	return vt, false
}

func authenticateUser(c *Configuration, rw http.ResponseWriter, req *http.Request) (u *User, halt bool) {
	var vt *jwt.Token

	var eh ErrorHandlerFunc
	if c.errorHandler == nil {
		eh = validationErrorToHTTPStatus
	} else {
		eh = c.errorHandler
	}

	if t, h := authenticate(c, rw, req); h {
		return nil, h
	} else {
		vt = t
	}

	u, err := newUser(vt)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	return u, false
}

func authenticateUserWithToken(c *Configuration, rw http.ResponseWriter, req *http.Request) (u *User, vt *jwt.Token, halt bool) {
	var eh ErrorHandlerFunc
	if c.errorHandler == nil {
		eh = validationErrorToHTTPStatus
	} else {
		eh = c.errorHandler
	}

	if t, h := authenticate(c, rw, req); h {
		return nil, nil, h
	} else {
		vt = t
	}

	u, err := newUser(vt)

	if err != nil {
		return nil, nil, eh(err, rw, req)
	}

	return u, vt, false
}
