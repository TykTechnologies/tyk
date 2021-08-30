package gateway

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

func DetermineGraphQLEngineTransportType(apiSpec *APISpec) GraphQLEngineTransportType {
	switch apiSpec.GraphQL.ExecutionMode {
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

type GraphQLEngineTransport struct {
	originalTransport http.RoundTripper
	transportType     GraphQLEngineTransportType
}

func NewGraphQLEngineTransport(transportType GraphQLEngineTransportType, originalTransport http.RoundTripper) *GraphQLEngineTransport {
	return &GraphQLEngineTransport{
		originalTransport: originalTransport,
		transportType:     transportType,
	}
}

func (g *GraphQLEngineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	switch g.transportType {
	case GraphQLEngineTransportTypeProxyOnly:
		proxyOnlyCtx, ok := request.Context().(*GraphQLProxyOnlyContext)
		if ok {
			return g.handleProxyOnly(proxyOnlyCtx, request)
		}
	}

	return g.originalTransport.RoundTrip(request)
}

func (g *GraphQLEngineTransport) handleProxyOnly(proxyOnlyCtx *GraphQLProxyOnlyContext, request *http.Request) (*http.Response, error) {
	request.Method = proxyOnlyCtx.forwardedRequest.Method
	g.setProxyOnlyHeaders(proxyOnlyCtx, request)

	response, err := g.originalTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	proxyOnlyCtx.upstreamResponse = response
	return response, err
}

func (g *GraphQLEngineTransport) setProxyOnlyHeaders(proxyOnlyCtx *GraphQLProxyOnlyContext, r *http.Request) {
	for forwardedHeaderKey, forwardedHeaderValues := range proxyOnlyCtx.forwardedRequest.Header {
		if proxyOnlyCtx.ignoreForwardedHeaders[forwardedHeaderKey] {
			continue
		}

		for _, forwardedHeaderValue := range forwardedHeaderValues {
			r.Header.Add(forwardedHeaderKey, forwardedHeaderValue)
		}
	}
}
