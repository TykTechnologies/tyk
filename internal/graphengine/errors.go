package graphengine

import (
	"errors"
	"io"
	"net/http"

	"github.com/TykTechnologies/tyk/header"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
	ErrIntrospectionDisabled     = errors.New("introspection is disabled")
	ErrUnknownReverseProxyType   = errors.New("unknown reverse proxy type")
)

// GraphQLErrors is what GraphQlError can render: an error that serializes itself as a
// GraphQL error response. RequestErrors from graphql-go-tools v1 and v2 both satisfy it.
type GraphQLErrors interface {
	error
	WriteResponse(w io.Writer) (int, error)
}

// GraphQlError defers writing a GraphQL validation error to the gateway error handler,
// so error overrides can replace it, while the body is still rendered by the error's own library.
type GraphQlError struct {
	err GraphQLErrors
}

func (e GraphQlError) Error() string {
	return e.err.Error()
}

func (e GraphQlError) Unwrap() error {
	return e.err
}

func (e GraphQlError) WriteToResponse(w http.ResponseWriter, statusCode int) error {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(statusCode)
	_, err := e.err.WriteResponse(w)
	return err
}
