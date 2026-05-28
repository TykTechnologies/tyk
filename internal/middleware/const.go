package middleware

import "errors"

// StatusRespond should be returned by a middleware to stop processing
// further middleware from the middleware chain.
const StatusRespond = 666

// ErrResponseRendered signals that a middleware has already written
// the full response (status, headers, body) and the chain's default
// error handler must not overlay an additional template / JSON-RPC
// envelope on top. Wrap the actual middleware error with `%w` so the
// dispatcher's `errors.Is` check can detect it.
var ErrResponseRendered = errors.New("response already rendered by middleware")
