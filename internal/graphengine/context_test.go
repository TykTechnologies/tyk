package graphengine

import (
	"context"
	"net/http"
	"sync"
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

func TestSubscriptionRequestContext(t *testing.T) {
	newRequestWithTransportValues := func(t *testing.T, roundTripper http.RoundTripper) (*http.Request, context.CancelFunc) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, "http://gateway.example/graphql", nil)
		require.NoError(t, err)
		requestCtx, cancelRequest := context.WithCancel(request.Context())
		requestCtx = SetGraphQLEngineTransportContextValue(requestCtx, roundTripper, ReverseProxyHeadersConfig{
			ProxyOnly: ProxyOnlyHeadersConfig{UseImmutableHeaders: true},
		})
		return request.WithContext(requestCtx), cancelRequest
	}

	t.Run("should carry the transport values of the request", func(t *testing.T) {
		roundTripper := taggedRoundTripper("caller")
		request, cancelRequest := newRequestWithTransportValues(t, roundTripper)
		defer cancelRequest()

		subscriptionCtx := subscriptionRequestContext(context.Background(), request)

		values := getGraphQLEngineTransportContextValue(subscriptionCtx)
		require.NotNil(t, values)
		assert.Equal(t, roundTripper, values.roundTripper)
		assert.True(t, values.headersConfig.ProxyOnly.UseImmutableHeaders)
	})

	// This is the regression guard for the websocket handover: net/http cancels the request
	// context as soon as ServeHTTP returns, which happens as soon as the connection is
	// hijacked, so a subscription must not inherit that cancellation.
	t.Run("should not inherit the cancellation of the request", func(t *testing.T) {
		request, cancelRequest := newRequestWithTransportValues(t, taggedRoundTripper("caller"))

		subscriptionCtx := subscriptionRequestContext(context.Background(), request)
		cancelRequest()

		require.Error(t, request.Context().Err(), "the request context should be cancelled")
		assert.NoError(t, subscriptionCtx.Err(), "the subscription context should still be alive")
	})

	t.Run("should be cancelled together with the engine", func(t *testing.T) {
		request, cancelRequest := newRequestWithTransportValues(t, taggedRoundTripper("caller"))
		defer cancelRequest()
		engineCtx, cancelEngine := context.WithCancel(context.Background())

		subscriptionCtx := subscriptionRequestContext(engineCtx, request)
		require.NoError(t, subscriptionCtx.Err())
		cancelEngine()

		assert.ErrorIs(t, subscriptionCtx.Err(), context.Canceled)
	})

	t.Run("should tolerate a nil engine context and a nil request", func(t *testing.T) {
		request, cancelRequest := newRequestWithTransportValues(t, taggedRoundTripper("caller"))
		defer cancelRequest()

		assert.NotNil(t, subscriptionRequestContext(nil, request))
		assert.NotNil(t, subscriptionRequestContext(nil, nil))
		assert.Nil(t, getGraphQLEngineTransportContextValue(subscriptionRequestContext(context.Background(), nil)))
	})
}

func TestGraphQLProxyOnlyContextValues_UpstreamResponse(t *testing.T) {
	t.Run("should return nil before the transport stored a response", func(t *testing.T) {
		values := &GraphQLProxyOnlyContextValues{}

		assert.Nil(t, values.getUpstreamResponse())
	})

	t.Run("should return the response the transport stored", func(t *testing.T) {
		values := &GraphQLProxyOnlyContextValues{}
		response := &http.Response{StatusCode: http.StatusTeapot}

		values.setUpstreamResponse(response)

		assert.Same(t, response, values.getUpstreamResponse())
	})

	// The transport writes from the fetch goroutine while the engine reads from the request
	// goroutine, which for a subscription can be a different one. Run under -race.
	t.Run("should be safe for concurrent use", func(t *testing.T) {
		values := &GraphQLProxyOnlyContextValues{}
		var waitGroup sync.WaitGroup
		for i := 0; i < 50; i++ {
			waitGroup.Add(2)
			go func() {
				defer waitGroup.Done()
				values.setUpstreamResponse(&http.Response{StatusCode: http.StatusOK})
			}()
			go func() {
				defer waitGroup.Done()
				_ = values.getUpstreamResponse()
			}()
		}
		waitGroup.Wait()

		assert.NotNil(t, values.getUpstreamResponse())
	})
}
