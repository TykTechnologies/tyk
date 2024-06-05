package graphengine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGraphQLEngineTransport_RoundTrip(t *testing.T) {
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

func testReusableReadCloser(readCloser io.ReadCloser) (io.ReadCloser, error) {
	return readCloser, nil
}
