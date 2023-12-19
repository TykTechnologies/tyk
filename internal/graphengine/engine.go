//go:generate mockgen -destination=./engine_mock_test.go -package=graphengine . Engine,ComplexityChecker,GraphQLRequestProcessor,GranularAccessChecker,ReverseProxyPreHandler
package graphengine

import (
	"context"
	"io"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/TykTechnologies/tyk/apidef"
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
	HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error)
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
	WebSocketUpgrader  *websocket.Upgrader
	NeedsEngine        bool
	IsCORSPreflight    bool
	IsWebSocketUpgrade bool
}

type ReverseProxyPreHandler interface {
	PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error)
}

type TransportModifier func(roundTripper http.RoundTripper, apiDefinition *apidef.APIDefinition) http.RoundTripper
