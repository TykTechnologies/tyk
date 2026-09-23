package graphengine

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/header"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	errCustomBodyResponse        = errors.New("errCustomBodyResponse")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
	ErrIntrospectionDisabled     = errors.New("introspection is disabled")
	ErrUnknownReverseProxyType   = errors.New("unknown reverse proxy type")
)

type GraphQlError struct {
	graphql.Errors
}

func (e GraphQlError) WriteToResponse(w http.ResponseWriter, statusCode int) error {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	w.WriteHeader(statusCode)
	_, err := e.WriteResponse(w)
	return err
}
