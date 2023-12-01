package graphengine

import (
	"errors"
)

var (
	ProxyingRequestFailedErr     = errors.New("there was a problem proxying the request")
	errCustomBodyResponse        = errors.New("errCustomBodyResponse")
	GraphQLDepthLimitExceededErr = errors.New("depth limit exceeded")
)
