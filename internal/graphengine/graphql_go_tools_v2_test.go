package graphengine

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

func TestReverseProxyPreHandlerV2_PreHandle(t *testing.T) {
	t.Run("should return error on CORS preflight request", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodOptions,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:      request,
			NeedsEngine:     true,
			IsCORSPreflight: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypePreFlight, result)
	})

	t.Run("should return ReverseProxyTypeWebsocketUpgrade on websocket upgrade", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			return nil // an upgrade request won't contain a graphql operation
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:         request,
			NeedsEngine:        true,
			IsWebSocketUpgrade: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeWebsocketUpgrade, result)
	})

	t.Run("should return ReverseProxyTypeIntrospection on introspection request", func(t *testing.T) {
		operation := testIntrospectionQuery

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest: request,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeIntrospection, result)
	})

	t.Run("should return ReverseProxyTypeGraphEngine if engine is needed", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:  request,
			NeedsEngine: true,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeGraphEngine, result)
	})

	t.Run("should return ReverseProxyTypeNone if no engine is needed", func(t *testing.T) {
		operation := `{ hello }`

		request, err := http.NewRequest(
			http.MethodPost,
			"http://example.com",
			bytes.NewBuffer([]byte(
				fmt.Sprintf(`{"query": "%s"}`, operation),
			)))
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(r *http.Request) *graphqlv2.Request {
			if r == request {
				return &graphqlv2.Request{
					Query: operation,
				}
			}

			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:  request,
			NeedsEngine: false,
		})
		assert.NoError(t, err)
		assert.Equal(t, ReverseProxyTypeNone, result)
	})

	t.Run("should attach the round tripper and the headers config to the request context", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(_ *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{Query: `{ hello }`}
		}
		headersConfig := ReverseProxyHeadersConfig{
			ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: true},
		}

		_, err = reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:    request,
			NeedsEngine:   true,
			RoundTripper:  taggedRoundTripper("caller"),
			HeadersConfig: headersConfig,
		})
		require.NoError(t, err)

		// The values have to be readable through the request the caller owns.
		values := getGraphQLEngineTransportContextValue(request.Context())
		require.NotNil(t, values)
		assert.Equal(t, taggedRoundTripper("caller"), values.roundTripper)
		assert.Equal(t, headersConfig, values.headersConfig)
	})

	t.Run("should attach the round tripper on a request that does not reach the engine", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodOptions, "http://example.com", nil)
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(_ *http.Request) *graphqlv2.Request {
			return nil
		}

		result, err := reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:      request,
			IsCORSPreflight: true,
			RoundTripper:    taggedRoundTripper("caller"),
		})
		require.NoError(t, err)
		require.Equal(t, ReverseProxyTypePreFlight, result)

		values := getGraphQLEngineTransportContextValue(request.Context())
		require.NotNil(t, values)
		assert.Equal(t, taggedRoundTripper("caller"), values.roundTripper)
	})

	t.Run("should not modify the transport of the shared http client", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)

		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(_ *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{Query: `{ hello }`}
		}
		configureGraphQLEngineHTTPClient(
			reverseProxyPreHandler.httpClient,
			DetermineGraphQLEngineTransportType(reverseProxyPreHandler.apiDefinition),
			testReusableReadCloser,
		)
		configuredTransport := reverseProxyPreHandler.httpClient.Transport

		_, err = reverseProxyPreHandler.PreHandle(ReverseProxyParams{
			OutRequest:   request,
			NeedsEngine:  true,
			RoundTripper: taggedRoundTripper("caller"),
		})
		require.NoError(t, err)

		assert.Same(t, configuredTransport, reverseProxyPreHandler.httpClient.Transport)
	})

	t.Run("should keep the round tripper of every request when called more than once", func(t *testing.T) {
		reverseProxyPreHandler := newTestReverseProxyPreHandlerV2(t)
		reverseProxyPreHandler.ctxRetrieveGraphQLRequest = func(_ *http.Request) *graphqlv2.Request {
			return &graphqlv2.Request{Query: `{ hello }`}
		}

		requests := make([]*http.Request, 0, 2)
		for _, tag := range []string{"caller-a", "caller-b"} {
			request, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
			require.NoError(t, err)
			_, err = reverseProxyPreHandler.PreHandle(ReverseProxyParams{
				OutRequest:   request,
				NeedsEngine:  true,
				RoundTripper: taggedRoundTripper(tag),
			})
			require.NoError(t, err)
			requests = append(requests, request)
		}

		for i, tag := range []string{"caller-a", "caller-b"} {
			values := getGraphQLEngineTransportContextValue(requests[i].Context())
			require.NotNil(t, values)
			assert.Equal(t, taggedRoundTripper(tag), values.roundTripper)
		}
	})
}

func newTestReverseProxyPreHandlerV2(t *testing.T) *reverseProxyPreHandlerV2 {
	return &reverseProxyPreHandlerV2{
		apiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			},
		},
		httpClient: &http.Client{},
		newReusableBodyReadCloser: func(closer io.ReadCloser) (io.ReadCloser, error) {
			return closer, nil
		},
	}
}
