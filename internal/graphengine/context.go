package graphengine

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

type GraphQLEngineTransportType int

const (
	GraphQLEngineTransportTypeProxyOnly GraphQLEngineTransportType = iota
	GraphQLEngineTransportTypeMultiUpstream
)

type contextKey struct{}

var graphqlProxyContextInfo = contextKey{}

type GraphQLProxyOnlyContextValues struct {
	forwardedRequest       *http.Request
	upstreamResponse       *http.Response
	ignoreForwardedHeaders map[string]bool
}

func SetProxyOnlyContextValue(ctx context.Context, req *http.Request) context.Context {
	value := &GraphQLProxyOnlyContextValues{
		forwardedRequest: req,
		ignoreForwardedHeaders: map[string]bool{
			http.CanonicalHeaderKey("date"):           true,
			http.CanonicalHeaderKey("content-type"):   true,
			http.CanonicalHeaderKey("content-length"): true,
		},
	}

	return context.WithValue(ctx, graphqlProxyContextInfo, value)
}

func GetProxyOnlyContextValue(ctx context.Context) *GraphQLProxyOnlyContextValues {
	val, ok := ctx.Value(graphqlProxyContextInfo).(*GraphQLProxyOnlyContextValues)
	if !ok {
		return nil
	}
	return val
}

func DetermineGraphQLEngineTransportType(apiDefinition *apidef.APIDefinition) GraphQLEngineTransportType {
	switch apiDefinition.GraphQL.ExecutionMode {
	case apidef.GraphQLExecutionModeSubgraph:
		fallthrough
	case apidef.GraphQLExecutionModeProxyOnly:
		return GraphQLEngineTransportTypeProxyOnly
	}

	return GraphQLEngineTransportTypeMultiUpstream
}

type GraphQLProxyOnlyContext struct {
	context.Context
	forwardedRequest       *http.Request
	upstreamResponse       *http.Response
	ignoreForwardedHeaders map[string]bool
}

func NewGraphQLProxyOnlyContext(ctx context.Context, forwardedRequest *http.Request) *GraphQLProxyOnlyContext {
	return &GraphQLProxyOnlyContext{
		Context:          ctx,
		forwardedRequest: forwardedRequest,
		ignoreForwardedHeaders: map[string]bool{
			http.CanonicalHeaderKey("date"):           true,
			http.CanonicalHeaderKey("content-type"):   true,
			http.CanonicalHeaderKey("content-length"): true,
		},
	}
}

func (g *GraphQLProxyOnlyContext) Response() *http.Response {
	return g.upstreamResponse
}
