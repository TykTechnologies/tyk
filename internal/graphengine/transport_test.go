package graphengine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLEngineTransport_RoundTrip(t *testing.T) {
	t.Run("uses the transport attached to each request context", func(t *testing.T) {
		fallback := taggedRoundTripper("fallback")
		transport := NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeMultiUpstream,
			fallback,
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)

		type result struct {
			want string
			got  string
			err  error
		}
		results := make(chan result, 100)
		for i := 0; i < cap(results); i++ {
			tag := []string{"caller-a", "caller-b"}[i%2]
			go func() {
				request, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", nil)
				if err != nil {
					results <- result{want: tag, err: err}
					return
				}
				ctx := SetGraphQLEngineTransportContextValue(request.Context(), taggedRoundTripper(tag), ReverseProxyHeadersConfig{})
				response, err := transport.RoundTrip(request.WithContext(ctx))
				if err != nil {
					results <- result{want: tag, err: err}
					return
				}
				results <- result{want: tag, got: response.Header.Get("X-Transport")}
			}()
		}
		for i := 0; i < cap(results); i++ {
			result := <-results
			require.NoError(t, result.err)
			assert.Equal(t, result.want, result.got)
		}
	})

	t.Run("falls back to the transport of the client when the request context carries none", func(t *testing.T) {
		transport := NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeMultiUpstream,
			taggedRoundTripper("fallback"),
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)

		request, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", nil)
		require.NoError(t, err)

		response, err := transport.RoundTrip(request)
		require.NoError(t, err)
		assert.Equal(t, "fallback", response.Header.Get("X-Transport"))
	})

	t.Run("falls back to the transport of the client when the request context carries a nil round tripper", func(t *testing.T) {
		transport := NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeMultiUpstream,
			taggedRoundTripper("fallback"),
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)

		request, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", nil)
		require.NoError(t, err)
		ctx := SetGraphQLEngineTransportContextValue(request.Context(), nil, ReverseProxyHeadersConfig{})

		response, err := transport.RoundTrip(request.WithContext(ctx))
		require.NoError(t, err)
		assert.Equal(t, "fallback", response.Header.Get("X-Transport"))
	})

	t.Run("uses http.DefaultTransport when the client has no transport at all", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusTeapot)
		}))
		t.Cleanup(upstream.Close)

		transport := NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeMultiUpstream,
			nil,
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)
		require.Equal(t, http.DefaultTransport, transport.originalTransport)

		request, err := http.NewRequest(http.MethodPost, upstream.URL, nil)
		require.NoError(t, err)

		response, err := transport.RoundTrip(request)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = response.Body.Close()
		})
		assert.Equal(t, http.StatusTeapot, response.StatusCode)
	})

	t.Run("prefers the headers config of the request over the one of the client", func(t *testing.T) {
		// The client is configured with the opposite of what every request asks for,
		// so a leaking client-level config would be visible in the forwarded headers.
		t.Run("should overwrite request headers when the request turns use_immutable_headers off", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{
					ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: true},
				},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "Bearer 123",
			})
			require.NoError(t, err)
			ctx = SetGraphQLEngineTransportContextValue(ctx, nopRoundTripper{}, ReverseProxyHeadersConfig{
				ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: false},
			})

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "none",
			})
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Equal(t, "none", outboundRequest.Header.Get("Authorization"))
		})

		t.Run("should not overwrite request headers when the request turns use_immutable_headers on", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{
					ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: false},
				},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "Bearer 123",
			})
			require.NoError(t, err)
			ctx = SetGraphQLEngineTransportContextValue(ctx, nopRoundTripper{}, ReverseProxyHeadersConfig{
				ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: true},
			})

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "none",
			})
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Equal(t, "Bearer 123", outboundRequest.Header.Get("Authorization"))
		})

		t.Run("should apply the request headers rewrite rules of the request", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, nil)
			require.NoError(t, err)
			ctx = SetGraphQLEngineTransportContextValue(ctx, nopRoundTripper{}, ReverseProxyHeadersConfig{
				ProxyOnly: ProxyOnlyHeadersConfig{
					RequestHeadersRewrite: map[string]apidef.RequestHeadersRewriteConfig{
						"X-Overwritten": {Value: "rewritten"},
						"X-Removed":     {Remove: true},
						"X-Added":       {Value: "added"},
					},
				},
			})

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"X-Overwritten": "from-client",
				"X-Removed":     "from-client",
			})
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Equal(t, "rewritten", outboundRequest.Header.Get("X-Overwritten"))
			assert.Empty(t, outboundRequest.Header.Values("X-Removed"))
			assert.Equal(t, "added", outboundRequest.Header.Get("X-Added"))
		})

		t.Run("should not apply the request headers rewrite rules of the client", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{
					ProxyOnly: ProxyOnlyHeadersConfig{
						RequestHeadersRewrite: map[string]apidef.RequestHeadersRewriteConfig{
							"X-Leaked": {Value: "leaked"},
						},
					},
				},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, nil)
			require.NoError(t, err)
			ctx = SetGraphQLEngineTransportContextValue(ctx, nopRoundTripper{}, ReverseProxyHeadersConfig{})

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, nil)
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Empty(t, outboundRequest.Header.Values("X-Leaked"))
		})
	})

	t.Run("feature use_immutable_headers", func(t *testing.T) {
		t.Run("should overwrite request headers when use_immutable_headers is false", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{
					ProxyOnly: ProxyOnlyHeadersConfig{
						UseImmutableHeaders: false,
					},
				},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "Bearer 123",
			})
			require.NoError(t, err)

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "none",
				"X-Custom":      "added-custom-value",
			})
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Equal(t, "none", outboundRequest.Header.Get("Authorization"))
			assert.Equal(t, "added-custom-value", outboundRequest.Header.Get("X-Custom"))
		})

		t.Run("should not overwrite request headers when use_immutable_headers is true", func(t *testing.T) {
			transport := NewGraphQLEngineTransport(
				GraphQLEngineTransportTypeProxyOnly,
				nopRoundTripper{},
				testReusableReadCloser,
				ReverseProxyHeadersConfig{
					ProxyOnly: ProxyOnlyHeadersConfig{
						UseImmutableHeaders: true,
					},
				},
			)

			_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "Bearer 123",
			})
			require.NoError(t, err)

			outboundRequest, err := prepareOutboundRequest(ctx, http.MethodPost, "http://example.com/graphql", nil, map[string]string{
				"Authorization": "none",
				"X-Custom":      "added-custom-value",
			})
			require.NoError(t, err)

			_, err = transport.RoundTrip(outboundRequest)
			assert.NoError(t, err)
			assert.Equal(t, "Bearer 123", outboundRequest.Header.Get("Authorization"))
			assert.Equal(t, "added-custom-value", outboundRequest.Header.Get("X-Custom"))
		})
	})
}

func TestConfigureGraphQLEngineHTTPClient(t *testing.T) {
	t.Run("should not panic when the client is nil", func(t *testing.T) {
		assert.NotPanics(t, func() {
			configureGraphQLEngineHTTPClient(nil, GraphQLEngineTransportTypeMultiUpstream, testReusableReadCloser)
		})
	})

	t.Run("should keep the transport of the client as the fallback", func(t *testing.T) {
		client := &http.Client{Transport: taggedRoundTripper("client")}

		configureGraphQLEngineHTTPClient(client, GraphQLEngineTransportTypeMultiUpstream, testReusableReadCloser)

		transport, ok := client.Transport.(*GraphQLEngineTransport)
		require.True(t, ok, "the client transport should be wrapped")
		assert.Equal(t, taggedRoundTripper("client"), transport.originalTransport)
		assert.Equal(t, GraphQLEngineTransportTypeMultiUpstream, transport.transportType)
		assert.NotNil(t, transport.newReusableBodyReadCloser)
		assert.Equal(t, ReverseProxyHeadersConfig{}, transport.headersConfig)
	})

	t.Run("should fall back to http.DefaultTransport when the client has no transport", func(t *testing.T) {
		client := &http.Client{}

		configureGraphQLEngineHTTPClient(client, GraphQLEngineTransportTypeProxyOnly, testReusableReadCloser)

		transport, ok := client.Transport.(*GraphQLEngineTransport)
		require.True(t, ok, "the client transport should be wrapped")
		assert.Equal(t, http.DefaultTransport, transport.originalTransport)
		assert.Equal(t, GraphQLEngineTransportTypeProxyOnly, transport.transportType)
	})

	t.Run("should not wrap an already configured client twice", func(t *testing.T) {
		client := &http.Client{Transport: taggedRoundTripper("client")}

		configureGraphQLEngineHTTPClient(client, GraphQLEngineTransportTypeMultiUpstream, testReusableReadCloser)
		configured := client.Transport
		configureGraphQLEngineHTTPClient(client, GraphQLEngineTransportTypeProxyOnly, testReusableReadCloser)

		assert.Same(t, configured, client.Transport)
	})

	t.Run("should route a request through the round tripper of its own context", func(t *testing.T) {
		client := &http.Client{Transport: taggedRoundTripper("client")}
		configureGraphQLEngineHTTPClient(client, GraphQLEngineTransportTypeMultiUpstream, testReusableReadCloser)

		request, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", nil)
		require.NoError(t, err)
		ctx := SetGraphQLEngineTransportContextValue(request.Context(), taggedRoundTripper("caller"), ReverseProxyHeadersConfig{})

		response, err := client.Do(request.WithContext(ctx))
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = response.Body.Close()
		})
		assert.Equal(t, "caller", response.Header.Get("X-Transport"))
	})
}

func prepareInboundRequest(method string, url string, body io.Reader, headers map[string]string) (*http.Request, context.Context, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	ctx := SetProxyOnlyContextValue(req.Context(), req)
	return req, ctx, err
}

func prepareOutboundRequest(ctx context.Context, method string, url string, body io.Reader, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	req = req.WithContext(ctx)
	return req, err
}

type nopRoundTripper struct{}

func (m nopRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := httptest.NewRecorder()
	resp.WriteHeader(http.StatusOK)
	return resp.Result(), nil
}

type taggedRoundTripper string

func (t taggedRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	response.Header().Set("X-Transport", string(t))
	response.WriteHeader(http.StatusOK)
	return response.Result(), nil
}

func testReusableReadCloser(readCloser io.ReadCloser) (io.ReadCloser, error) {
	return readCloser, nil
}
