package graphengine

import (
	"context"
	"net/http"
	"sync"

	"github.com/TykTechnologies/tyk/apidef"
)

type GraphQLEngineTransportType int

const (
	GraphQLEngineTransportTypeProxyOnly GraphQLEngineTransportType = iota
	GraphQLEngineTransportTypeMultiUpstream
)

type contextKey struct{}

type transportContextKey struct{}

var graphqlProxyContextInfo = contextKey{}
var graphqlTransportContextInfo = transportContextKey{}

type graphQLEngineTransportContextValues struct {
	roundTripper  http.RoundTripper
	headersConfig ReverseProxyHeadersConfig
}

func SetGraphQLEngineTransportContextValue(ctx context.Context, roundTripper http.RoundTripper, headersConfig ReverseProxyHeadersConfig) context.Context {
	value := &graphQLEngineTransportContextValues{
		roundTripper:  roundTripper,
		headersConfig: headersConfig,
	}
	return context.WithValue(ctx, graphqlTransportContextInfo, value)
}

func copyGraphQLEngineTransportContextValue(target, source context.Context) context.Context {
	value, ok := source.Value(graphqlTransportContextInfo).(*graphQLEngineTransportContextValues)
	if !ok || value == nil {
		return target
	}
	return context.WithValue(target, graphqlTransportContextInfo, value)
}

func getGraphQLEngineTransportContextValue(ctx context.Context) *graphQLEngineTransportContextValues {
	value, ok := ctx.Value(graphqlTransportContextInfo).(*graphQLEngineTransportContextValues)
	if !ok {
		return nil
	}
	return value
}

// subscriptionRequestContext returns the context that a websocket subscription handler
// runs on. It carries the transport values of the request that opened the connection, so
// upstream fetches keep using that caller's round tripper, but it is rooted at the long
// lived engine context so that releasing the API ends the subscription.
//
// The request context cannot be used as the parent: net/http cancels it as soon as
// ServeHTTP returns, and the gateway returns as soon as the connection is hijacked, so a
// subscription rooted there is cancelled before it delivers anything.
func subscriptionRequestContext(engineCtx context.Context, outreq *http.Request) context.Context {
	if engineCtx == nil {
		engineCtx = context.Background()
	}
	if outreq == nil {
		return engineCtx
	}
	return copyGraphQLEngineTransportContextValue(engineCtx, outreq.Context())
}

type GraphQLProxyOnlyContextValues struct {
	forwardedRequest       *http.Request
	ignoreForwardedHeaders map[string]bool

	// upstreamResponse is written by the transport and read by the engine. Those can be
	// different goroutines: a subscription fetch runs on the resolver's trigger goroutine
	// and can outlive the handover that reads the response, so both sides go through the
	// accessors below.
	mu               sync.Mutex
	upstreamResponse *http.Response
}

func (g *GraphQLProxyOnlyContextValues) setUpstreamResponse(response *http.Response) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.upstreamResponse = response
}

func (g *GraphQLProxyOnlyContextValues) getUpstreamResponse() *http.Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.upstreamResponse
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
