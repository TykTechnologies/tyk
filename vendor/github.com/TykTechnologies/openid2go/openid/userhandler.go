package openid

import "net/http"

// The UserHandler represents a handler to be registered by the middleware AuthenticateUser.
// This handler allows the AuthenticateUser middleware to forward information about the the authenticated user to
// the rest of the application service.
//
// ServeHTTPWithUser is similar to the http.ServeHTTP function. It contains an additional paramater *User,
// which is used by the AuthenticateUser middleware to pass information about the authenticated user.
type UserHandler interface {
	ServeHTTPWithUser(*User, http.ResponseWriter, *http.Request)
}

// The UserHandlerFunc is an adapter to allow the use of functions as UserHandler.
// This is similar to using http.HandlerFunc as http.Handler
type UserHandlerFunc func(*User, http.ResponseWriter, *http.Request)

// ServeHttpWithUser calls f(u, w, r)
func (f UserHandlerFunc) ServeHTTPWithUser(u *User, w http.ResponseWriter, r *http.Request) {
	f(u, w, r)
}
