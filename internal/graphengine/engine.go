package graphengine

import (
	"context"
	"io"
	"net/http"
)

type ProcessGraphQLComplexityParams struct {
	w http.ResponseWriter
	r *http.Request
}

type Engine interface {
	HasSchema() bool
	ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int)
	ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int)
	ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int)
	HandleReverseProxy(roundTripper http.RoundTripper, w http.ResponseWriter, r *http.Request) (res *http.Response, err error)
}

type ComplexityAccessDefinition struct {
	Limit             ComplexityLimit
	FieldAccessRights []ComplexityFieldAccessDefinition
}

type ComplexityLimit struct {
	MaxQueryDepth int
}

type ComplexityFieldAccessDefinition struct {
	TypeName  string
	FieldName string
	Limits    ComplexityFieldLimits
}

type ComplexityFieldLimits struct {
	MaxQueryDepth int
}

type ComplexityChecker interface {
	DepthLimitExceeded(r *http.Request, accessDefinition *ComplexityAccessDefinition) ComplexityFailReason
}

type GraphQLRequestProcessor interface {
	ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int)
}

type GraphQLGranularAccessResult struct {
	FailReason         GranularAccessFailReason
	ValidationError    error
	InternalErr        error
	writeErrorResponse func(w io.Writer, providedErr error) (n int, err error)
}

type GranularAccessDefinition struct {
	AllowedTypes    []GranularAccessType
	RestrictedTypes []GranularAccessType
}

type GranularAccessType struct {
	Name   string
	Fields []string
}

type GranularAccessChecker interface {
	CheckGraphQLRequestFieldAllowance(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) GraphQLGranularAccessResult
}

type ReverseProxyParams struct {
	RoundTripper       http.RoundTripper
	ResponseWriter     http.ResponseWriter
	OutRequest         *http.Request
	NeedsEngine        bool
	IsCORSPreflight    bool
	IsWebSocketUpgrade bool
}

type ReverseProxyHandler interface {
	Handle(params ReverseProxyParams) (res *http.Response, err error)
}
