package graphengine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
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
			assert.Equal(t, []string{"none", "Bearer 123"}, outboundRequest.Header.Values("Authorization"))
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
			assert.Equal(t, []string{"Bearer 123"}, outboundRequest.Header.Values("Authorization"))
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
			// Both values reach the upstream, the engine's first. Asserted as a list
			// because Get would hide a duplicate.
			assert.Equal(t, []string{"none", "Bearer 123"}, outboundRequest.Header.Values("Authorization"))
			assert.Equal(t, []string{"added-custom-value"}, outboundRequest.Header.Values("X-Custom"))
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
			assert.Equal(t, []string{"Bearer 123"}, outboundRequest.Header.Values("Authorization"))
			assert.Equal(t, []string{"added-custom-value"}, outboundRequest.Header.Values("X-Custom"))
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

func TestGraphQLEngineTransport_ProxyOnlyMethod(t *testing.T) {
	newProxyOnlyTransport := func() *GraphQLEngineTransport {
		return NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeProxyOnly,
			nopRoundTripper{},
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)
	}

	t.Run("should take the method of the caller for a normal request", func(t *testing.T) {
		transport := newProxyOnlyTransport()
		_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, nil)
		require.NoError(t, err)
		outboundRequest, err := prepareOutboundRequest(ctx, http.MethodGet, "http://example.com/graphql", nil, nil)
		require.NoError(t, err)

		_, err = transport.RoundTrip(outboundRequest)
		require.NoError(t, err)

		assert.Equal(t, http.MethodPost, outboundRequest.Method)
	})

	// The upstream subscription handshake is a GET even when the caller used POST. Taking
	// the caller's method turns it into a POST, which every websocket server rejects.
	t.Run("should keep the method of a websocket handshake", func(t *testing.T) {
		transport := newProxyOnlyTransport()
		_, ctx, err := prepareInboundRequest(http.MethodPost, "http://example.com/graphql", nil, nil)
		require.NoError(t, err)
		outboundRequest, err := prepareOutboundRequest(ctx, http.MethodGet, "http://example.com/graphql", nil, map[string]string{
			"Connection": "Upgrade",
			"Upgrade":    "websocket",
		})
		require.NoError(t, err)

		_, err = transport.RoundTrip(outboundRequest)
		require.NoError(t, err)

		assert.Equal(t, http.MethodGet, outboundRequest.Method)
	})
}

func TestIsWebSocketHandshake(t *testing.T) {
	newRequest := func(t *testing.T, headers map[string]string) *http.Request {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, "http://example.com/graphql", nil)
		require.NoError(t, err)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		return request
	}

	t.Run("should detect a handshake", func(t *testing.T) {
		assert.True(t, isWebSocketHandshake(newRequest(t, map[string]string{
			"Connection": "Upgrade",
			"Upgrade":    "websocket",
		})))
	})

	t.Run("should ignore the case of the header values", func(t *testing.T) {
		assert.True(t, isWebSocketHandshake(newRequest(t, map[string]string{
			"Connection": "keep-alive, upgrade",
			"Upgrade":    "WebSocket",
		})))
	})

	t.Run("should not detect a handshake without both headers", func(t *testing.T) {
		assert.False(t, isWebSocketHandshake(newRequest(t, nil)))
		assert.False(t, isWebSocketHandshake(newRequest(t, map[string]string{"Upgrade": "websocket"})))
		assert.False(t, isWebSocketHandshake(newRequest(t, map[string]string{"Connection": "Upgrade"})))
		assert.False(t, isWebSocketHandshake(newRequest(t, map[string]string{
			"Connection": "Upgrade",
			"Upgrade":    "h2c",
		})))
	})
}

// The fallback round tripper serves the engines whose upstream requests cannot carry one of
// their own, which today is EngineV1 alone. It is the only state of the engine transport
// shared between callers, so it needs both the fallback behaviour and the locking.
func TestGraphQLEngineTransport_FallbackRoundTripper(t *testing.T) {
	newTransport := func() *GraphQLEngineTransport {
		return NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeMultiUpstream,
			taggedRoundTripper("original"),
			testReusableReadCloser,
			ReverseProxyHeadersConfig{},
		)
	}

	request := func(t *testing.T) *http.Request {
		t.Helper()
		outreq, err := http.NewRequest(http.MethodPost, "http://upstream.example/graphql", nil)
		require.NoError(t, err)
		return outreq
	}

	t.Run("falls back to the original transport when none was set", func(t *testing.T) {
		response, err := newTransport().RoundTrip(request(t))
		require.NoError(t, err)
		assert.Equal(t, "original", response.Header.Get("X-Transport"))
	})

	t.Run("uses the fallback for a request that carries no round tripper", func(t *testing.T) {
		transport := newTransport()
		transport.setFallbackRoundTripper(taggedRoundTripper("gateway"))

		response, err := transport.RoundTrip(request(t))
		require.NoError(t, err)
		assert.Equal(t, "gateway", response.Header.Get("X-Transport"))
	})

	t.Run("the round tripper of the request still wins over the fallback", func(t *testing.T) {
		// EngineV2 and EngineV3 stay fully request scoped: their fetches carry the round
		// tripper of the caller and must never reach the shared fallback.
		transport := newTransport()
		transport.setFallbackRoundTripper(taggedRoundTripper("gateway"))

		outreq := request(t)
		outreq = outreq.WithContext(SetGraphQLEngineTransportContextValue(
			outreq.Context(), taggedRoundTripper("caller"), ReverseProxyHeadersConfig{}))

		response, err := transport.RoundTrip(outreq)
		require.NoError(t, err)
		assert.Equal(t, "caller", response.Header.Get("X-Transport"))
	})

	t.Run("a nil round tripper does not clear the fallback", func(t *testing.T) {
		transport := newTransport()
		transport.setFallbackRoundTripper(taggedRoundTripper("gateway"))
		transport.setFallbackRoundTripper(nil)

		response, err := transport.RoundTrip(request(t))
		require.NoError(t, err)
		assert.Equal(t, "gateway", response.Header.Get("X-Transport"))
	})

	t.Run("refreshing the fallback while it is in use does not race", func(t *testing.T) {
		transport := newTransport()
		var waitGroup sync.WaitGroup
		for i := 0; i < 50; i++ {
			waitGroup.Add(2)
			go func(i int) {
				defer waitGroup.Done()
				transport.setFallbackRoundTripper(taggedRoundTripper(fmt.Sprintf("gateway-%02d", i)))
			}(i)
			go func() {
				defer waitGroup.Done()
				response, err := transport.RoundTrip(request(t))
				require.NoError(t, err)
				assert.NotEmpty(t, response.Header.Get("X-Transport"))
			}()
		}
		waitGroup.Wait()
	})
}

// setProxyOnlyHeaders forwards the consumer's headers onto the upstream request that the
// engine already built. Two writers meet here: with strip_auth_data off the engine has
// already put the consumer's auth header on the request through additionalUpstreamHeaders,
// and forwarding it again sends the credential upstream twice.
func TestGraphQLEngineTransport_SetProxyOnlyHeaders(t *testing.T) {
	// forward runs setProxyOnlyHeaders with the consumer's headers over the headers the
	// engine had already placed on the upstream request, and returns the result.
	forward := func(t *testing.T, useImmutableHeaders bool, engineHeader, consumerHeader http.Header) http.Header {
		t.Helper()
		inbound, err := http.NewRequest(http.MethodPost, "http://gateway.example/graphql", nil)
		require.NoError(t, err)
		inbound.Header = consumerHeader

		outbound, err := http.NewRequest(http.MethodPost, "http://upstream.example/graphql", nil)
		require.NoError(t, err)
		outbound.Header = engineHeader

		transport := NewGraphQLEngineTransport(
			GraphQLEngineTransportTypeProxyOnly,
			nopRoundTripper{},
			testReusableReadCloser,
			ReverseProxyHeadersConfig{
				ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: useImmutableHeaders},
			},
		)
		transport.setProxyOnlyHeaders(GetProxyOnlyContextValue(SetProxyOnlyContextValue(inbound.Context(), inbound)), outbound)
		return outbound.Header
	}

	t.Run("does not forward a value the engine already set", func(t *testing.T) {
		// The reported defect: the upstream received x-api-key twice, same value.
		header := forward(t, false,
			http.Header{"X-Api-Key": {"key-aaa"}},
			http.Header{"X-Api-Key": {"key-aaa"}})

		assert.Equal(t, []string{"key-aaa"}, header.Values("X-Api-Key"))
	})

	t.Run("keeps a differing configured value alongside the consumer's", func(t *testing.T) {
		// request_headers semantics, TT-11990 and TT-12190: with immutable headers off
		// both values reach the upstream.
		header := forward(t, false,
			http.Header{"X-Custom": {"from-request-headers"}},
			http.Header{"X-Custom": {"from-consumer"}})

		assert.Equal(t, []string{"from-request-headers", "from-consumer"}, header.Values("X-Custom"))
	})

	t.Run("the consumer wins when immutable headers are on", func(t *testing.T) {
		header := forward(t, true,
			http.Header{"X-Custom": {"from-request-headers"}},
			http.Header{"X-Custom": {"from-consumer"}})

		assert.Equal(t, []string{"from-consumer"}, header.Values("X-Custom"))
	})

	t.Run("keeps every value of a multi value consumer header when immutable headers are on", func(t *testing.T) {
		// The delete used to sit inside the value loop, so it removed the value added on
		// the previous pass and only the last one survived.
		header := forward(t, true,
			http.Header{"X-Custom": {"from-request-headers"}},
			http.Header{"X-Custom": {"first", "second", "third"}})

		assert.Equal(t, []string{"first", "second", "third"}, header.Values("X-Custom"))
	})

	t.Run("keeps every value of a multi value consumer header when immutable headers are off", func(t *testing.T) {
		header := forward(t, false,
			http.Header{},
			http.Header{"X-Custom": {"first", "second", "third"}})

		assert.Equal(t, []string{"first", "second", "third"}, header.Values("X-Custom"))
	})

	t.Run("forwards a duplicate the consumer itself sent", func(t *testing.T) {
		// Only an overlap with what the engine wrote is dropped. What the consumer sent
		// twice is none of this function's business.
		header := forward(t, false,
			http.Header{},
			http.Header{"X-Custom": {"same", "same"}})

		assert.Equal(t, []string{"same", "same"}, header.Values("X-Custom"))
	})

	t.Run("drops only the overlapping value of a partially overlapping header", func(t *testing.T) {
		header := forward(t, false,
			http.Header{"X-Custom": {"shared"}},
			http.Header{"X-Custom": {"shared", "extra"}})

		assert.Equal(t, []string{"shared", "extra"}, header.Values("X-Custom"))
	})

	t.Run("still skips the ignored headers", func(t *testing.T) {
		header := forward(t, false,
			http.Header{"Content-Type": {"application/json"}},
			http.Header{"Content-Type": {"text/plain"}, "Content-Length": {"12"}, "Date": {"now"}})

		assert.Equal(t, []string{"application/json"}, header.Values("Content-Type"))
		assert.Empty(t, header.Values("Content-Length"))
		assert.Empty(t, header.Values("Date"))
	})
}
