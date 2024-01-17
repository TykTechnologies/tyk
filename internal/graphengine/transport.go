package graphengine

import (
	"bytes"
	"io"
	"net/http"
)

type NewReusableBodyReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)
type SeekReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)

type GraphQLEngineTransport struct {
	originalTransport         http.RoundTripper
	transportType             GraphQLEngineTransportType
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

func NewGraphQLEngineTransport(transportType GraphQLEngineTransportType, originalTransport http.RoundTripper, newReusableBodyReadCloser NewReusableBodyReadCloserFunc) *GraphQLEngineTransport {
	transport := &GraphQLEngineTransport{
		originalTransport:         originalTransport,
		transportType:             transportType,
		newReusableBodyReadCloser: newReusableBodyReadCloser,
	}
	return transport
}

func (g *GraphQLEngineTransport) RoundTrip(request *http.Request) (res *http.Response, err error) {
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

	if response.StatusCode >= http.StatusBadRequest {
		// In proxy-only mode, we keep the upstream error message to
		// insert into the library's error message.
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = response.Body.Close()
		}()
		// graphql-go-tools uses response.body to resolve the upstream response.
		// It's not possible to re-use io.ReadCloser. Because of that, we keep the
		// original error message for later use.
		// See TT-7808
		reusableBody, err := g.newReusableBodyReadCloser(io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			return nil, err
		}
		response.Body = reusableBody
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
