package graphengine

import (
	"errors"
	"io"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/header"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
	ErrIntrospectionDisabled     = errors.New("introspection is disabled")
	ErrUnknownReverseProxyType   = errors.New("unknown reverse proxy type")
)

// GraphQlError carries a GraphQL validation error together with the engine-specific
// writer that renders it, so v1 and v2 errors are both serialized by their own library.
type GraphQlError struct {
	err   error
	write func(w io.Writer, err error) (int, error)
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
	return e.writeToResponse(w)
}

func (e GraphQlError) writeToResponse(w http.ResponseWriter) (err error) {
	if e.write == nil {
		_, err = graphql.RequestErrorsFromError(e.err).WriteResponse(w)
	} else {
		_, err = e.write(w, e.err)
	}

	return
}
