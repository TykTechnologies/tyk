package graphengine

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLEngineTransportContextValue(t *testing.T) {
	headersConfig := ReverseProxyHeadersConfig{
		ProxyOnly: ProxyOnlyHeadersConfig{
			UseImmutableHeaders: true,
			RequestHeadersRewrite: map[string]apidef.RequestHeadersRewriteConfig{
				"X-Custom": {Value: "rewritten", Remove: false},
			},
		},
	}

	t.Run("should return nil when no value is set", func(t *testing.T) {
		assert.Nil(t, getGraphQLEngineTransportContextValue(context.Background()))
	})

	t.Run("should return the round tripper and the headers config that were set", func(t *testing.T) {
		roundTripper := taggedRoundTripper("caller")

		ctx := SetGraphQLEngineTransportContextValue(context.Background(), roundTripper, headersConfig)

		values := getGraphQLEngineTransportContextValue(ctx)
		require.NotNil(t, values)
		assert.Equal(t, roundTripper, values.roundTripper)
		assert.Equal(t, headersConfig, values.headersConfig)
	})

	t.Run("should keep a nil round tripper as nil", func(t *testing.T) {
		ctx := SetGraphQLEngineTransportContextValue(context.Background(), nil, ReverseProxyHeadersConfig{})

		values := getGraphQLEngineTransportContextValue(ctx)
		require.NotNil(t, values)
		assert.Nil(t, values.roundTripper)
	})

	t.Run("should not read a foreign value stored under a different key", func(t *testing.T) {
		ctx := SetProxyOnlyContextValue(context.Background(), &http.Request{})

		assert.Nil(t, getGraphQLEngineTransportContextValue(ctx))
	})
}

func TestCopyGraphQLEngineTransportContextValue(t *testing.T) {
	t.Run("should copy the value of the source context into the target context", func(t *testing.T) {
		roundTripper := taggedRoundTripper("caller")
		source := SetGraphQLEngineTransportContextValue(context.Background(), roundTripper, ReverseProxyHeadersConfig{
			ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: true},
		})

		target := copyGraphQLEngineTransportContextValue(context.Background(), source)

		values := getGraphQLEngineTransportContextValue(target)
		require.NotNil(t, values)
		// The value is shared by reference, it is never rebuilt for the target context.
		assert.Same(t, getGraphQLEngineTransportContextValue(source), values)
		assert.Equal(t, roundTripper, values.roundTripper)
		assert.True(t, values.headersConfig.ProxyOnly.UseImmutableHeaders)
	})

	t.Run("should return the target context unchanged when the source has no value", func(t *testing.T) {
		target := context.Background()

		assert.Equal(t, target, copyGraphQLEngineTransportContextValue(target, context.Background()))
		assert.Nil(t, getGraphQLEngineTransportContextValue(copyGraphQLEngineTransportContextValue(target, context.Background())))
	})

	t.Run("should keep the values that the target context already carries", func(t *testing.T) {
		forwardedRequest, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", nil)
		require.NoError(t, err)
		target := SetProxyOnlyContextValue(context.Background(), forwardedRequest)
		source := SetGraphQLEngineTransportContextValue(context.Background(), taggedRoundTripper("caller"), ReverseProxyHeadersConfig{})

		target = copyGraphQLEngineTransportContextValue(target, source)

		require.NotNil(t, getGraphQLEngineTransportContextValue(target))
		proxyOnlyValues := GetProxyOnlyContextValue(target)
		require.NotNil(t, proxyOnlyValues)
		assert.Same(t, forwardedRequest, proxyOnlyValues.forwardedRequest)
	})

	t.Run("should overwrite a value that the target context already carries", func(t *testing.T) {
		target := SetGraphQLEngineTransportContextValue(context.Background(), taggedRoundTripper("stale"), ReverseProxyHeadersConfig{})
		source := SetGraphQLEngineTransportContextValue(context.Background(), taggedRoundTripper("current"), ReverseProxyHeadersConfig{})

		target = copyGraphQLEngineTransportContextValue(target, source)

		values := getGraphQLEngineTransportContextValue(target)
		require.NotNil(t, values)
		assert.Equal(t, taggedRoundTripper("current"), values.roundTripper)
	})
}
