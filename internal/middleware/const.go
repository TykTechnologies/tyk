package middleware

import "errors"

// StatusRespond should be returned by a middleware to stop processing
// further middleware from the middleware chain.
const StatusRespond = 666

// ErrResponseRendered signals that a middleware already wrote the full response;
// the chain dispatcher must not overlay another error body on top.
var ErrResponseRendered = errors.New("response already rendered by middleware")
