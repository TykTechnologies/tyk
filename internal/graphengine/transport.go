package graphengine

import (
	"bytes"
	"io"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

type NewReusableBodyReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)
type SeekReadCloserFunc func(io.ReadCloser) (io.ReadCloser, error)

type GraphQLEngineTransport struct {
	originalTransport         http.RoundTripper
	transportType             GraphQLEngineTransportType
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	requestHeadersRewrite     map[string]apidef.RequestHeadersRewriteConfig
}

func NewGraphQLEngineTransport(
	transportType GraphQLEngineTransportType,
	originalTransport http.RoundTripper,
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc,
	requestHeadersRewrite map[string]apidef.RequestHeadersRewriteConfig,
) *GraphQLEngineTransport {
	transport := &GraphQLEngineTransport{
		originalTransport:         originalTransport,
		transportType:             transportType,
		newReusableBodyReadCloser: newReusableBodyReadCloser,
		requestHeadersRewrite:     requestHeadersRewrite,
	}
	return transport
}

func (g *GraphQLEngineTransport) RoundTrip(request *http.Request) (res *http.Response, err error) {
	switch g.transportType {
	case GraphQLEngineTransportTypeProxyOnly:
		val := GetProxyOnlyContextValue(request.Context())
		if val != nil {
			return g.handleProxyOnly(val, request)
		}
	}

	return g.originalTransport.RoundTrip(request)
}

func (g *GraphQLEngineTransport) handleProxyOnly(proxyOnlyValues *GraphQLProxyOnlyContextValues, request *http.Request) (*http.Response, error) {
	request.Method = proxyOnlyValues.forwardedRequest.Method
	g.setProxyOnlyHeaders(proxyOnlyValues, request)
	g.applyRequestHeadersRewriteRules(request)

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
	proxyOnlyValues.upstreamResponse = response
	return response, err
}

func (g *GraphQLEngineTransport) applyRequestHeadersRewriteRules(r *http.Request) {
	if len(g.requestHeadersRewrite) == 0 {
		// There is no request rewrite rule, quit early.
		return
	}

	ruleOne := func(r *http.Request, key string, values []string) bool {
		// Rule one:
		//
		// If header key/value is defined in request_headers_rewrite and remove
		// is set to false and client sends a request with the same header key but
		// different value, the value gets overwritten to the defined value before
		// hitting the upstream.

		rewriteRule, ok := g.requestHeadersRewrite[key]
		if !ok {
			return false // key not exists, not apply the rule
		}
		if !rewriteRule.Remove {
			if len(values) > 1 || values[0] != rewriteRule.Value {
				// Has more than one value, so it's different.
				// OR
				// It has only one value, check and overwrite it if required.
				r.Header.Del(key)
				r.Header.Set(key, rewriteRule.Value)
				return true // applied
			}
		}
		return false // not applied
	}

	ruleTwo := func(r *http.Request, key string, values []string) bool {
		// Rule two:
		//
		// If header key is defined in request_headers_rewrite and remove is set
		// to true and client sends a request with the same header key but different value,
		// the headers gets removed completely before hitting the upstream.
		rewriteRule, ok := g.requestHeadersRewrite[key]
		if !ok {
			return false // key not exists, not apply the rule
		}
		if rewriteRule.Remove {
			if len(values) > 1 || values[0] != rewriteRule.Value {
				// Has more than one value, so it's different.
				// OR
				// It has only one value, check and overwrite it if required.
				r.Header.Del(key)
				return true // applied
			}
		}
		return false // not applied
	}

	// Try to apply rule one and rule two.
	for forwardedHeaderKey, forwardedHeaderValues := range r.Header {
		if len(forwardedHeaderValues) == 0 {
			// This should not be possible but this check makes the rest of code simpler.
			continue
		}

		if ruleOne(r, forwardedHeaderKey, forwardedHeaderValues) {
			continue
		}

		if ruleTwo(r, forwardedHeaderKey, forwardedHeaderValues) {
			continue
		}
	}

	// Rule three:
	//
	// If header key/value is defined in request_headers_rewrite and remove is
	// set to false and client sends a request that does not have the same header key,
	// the header key/value gets added before hitting the upstream.
	for headerKey, rewriteRule := range g.requestHeadersRewrite {
		if rewriteRule.Remove {
			continue
		}
		existingHeaderValue := r.Header.Get(headerKey)
		if existingHeaderValue == "" {
			r.Header.Set(headerKey, rewriteRule.Value)
		}
	}
}

func (g *GraphQLEngineTransport) setProxyOnlyHeaders(proxyOnlyValues *GraphQLProxyOnlyContextValues, r *http.Request) {
	for forwardedHeaderKey, forwardedHeaderValues := range proxyOnlyValues.forwardedRequest.Header {
		if proxyOnlyValues.ignoreForwardedHeaders[forwardedHeaderKey] {
			continue
		}

		for _, forwardedHeaderValue := range forwardedHeaderValues {
			exitingHeaderValue := r.Header.Get(forwardedHeaderKey)
			// Prioritize consumer's header value. Delete the header from request_headers
			// and add the consumer's value. See TT-11990.
			if exitingHeaderValue != "" {
				r.Header.Del(forwardedHeaderKey)
			}
			r.Header.Add(forwardedHeaderKey, forwardedHeaderValue)
		}
	}
}
