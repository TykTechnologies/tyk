package gateway

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestDetermineGraphQLEngineTransportType(t *testing.T) {
	testCases := []struct {
		name          string
		executionMode apidef.GraphQLExecutionMode
		expected      GraphQLEngineTransportType
	}{
		{
			name:          "should be 'MultiUpstream' for executionEngine",
			executionMode: apidef.GraphQLExecutionModeExecutionEngine,
			expected:      GraphQLEngineTransportTypeMultiUpstream,
		},
		{
			name:          "should be 'MultiUpstream' for supergraph",
			executionMode: apidef.GraphQLExecutionModeSupergraph,
			expected:      GraphQLEngineTransportTypeMultiUpstream,
		},
		{
			name:          "should be 'ProxyOnly' for proxyOnly",
			executionMode: apidef.GraphQLExecutionModeProxyOnly,
			expected:      GraphQLEngineTransportTypeProxyOnly,
		},
		{
			name:          "should be 'ProxyOnly' for subgraph",
			executionMode: apidef.GraphQLExecutionModeSubgraph,
			expected:      GraphQLEngineTransportTypeProxyOnly,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			apiSpec := &APISpec{
				APIDefinition: &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						ExecutionMode: tc.executionMode,
					},
				},
			}

			result := DetermineGraphQLEngineTransportType(apiSpec)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGraphQLEngineTransport_RoundTrip(t *testing.T) {
	type serverExpectations struct {
		method  string
		headers map[string]string
		body    string
	}

	type serverResponse struct {
		statusCode int
		headers    map[string]string
		body       string
	}

	newTestServer := func(t *testing.T, expectations serverExpectations, response serverResponse) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, expectations.method, r.Method)

			for expectedHeaderKey, expectedHeaderValue := range expectations.headers {
				if assert.Contains(t, r.Header, expectedHeaderKey) {
					assert.Equal(t, expectedHeaderValue, r.Header.Get(expectedHeaderKey))
				}
			}

			bodyBytes, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, expectations.body, string(bodyBytes))

			for responseHeaderKey, responseHeaderValue := range response.headers {
				w.Header().Set(responseHeaderKey, responseHeaderValue)
			}

			w.WriteHeader(response.statusCode)
			_, _ = w.Write([]byte(response.body))
		}))
	}

	t.Run("should handle proxy-only transport", func(t *testing.T) {
		expectations := serverExpectations{
			method: http.MethodPut,
			headers: map[string]string{
				http.CanonicalHeaderKey("X-Custom-Key"):  "custom-value",
				http.CanonicalHeaderKey("X-Other-Value"): "other-value",
			},
			body: `{"hello":"world"}`,
		}

		response := serverResponse{
			statusCode: http.StatusCreated,
			headers: map[string]string{
				http.CanonicalHeaderKey("X-Response-Key"): "response-value",
			},
			body: `{"ping":"pong}"`,
		}

		testServer := newTestServer(t, expectations, response)
		defer testServer.Close()

		forwardedRequest, err := http.NewRequest(http.MethodPut, "http://tyk-gateway:8080", bytes.NewBufferString(`{"ignoredByTransport":true}`))
		require.NoError(t, err)

		forwardedRequest.Header.Set("X-Custom-Key", "custom-value")
		forwardedRequest.Header.Set("X-Other-Value", "other-value")
		ctx := NewGraphQLProxyOnlyContext(context.Background(), forwardedRequest)

		httpClient := http.Client{
			Transport: NewGraphQLEngineTransport(GraphQLEngineTransportTypeProxyOnly, http.DefaultTransport),
		}

		upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, testServer.URL, bytes.NewBufferString(`{"hello":"world"}`))
		require.NoError(t, err)

		transportResponse, err := httpClient.Do(upstreamRequest)
		assert.Equal(t, response.statusCode, transportResponse.StatusCode)

		for expectedTransportResponseHeaderKey, expectedTransportResponseHeaderValue := range response.headers {
			if assert.Contains(t, transportResponse.Header, expectedTransportResponseHeaderKey) {
				assert.Equal(t, expectedTransportResponseHeaderValue, transportResponse.Header.Get(expectedTransportResponseHeaderKey))
			}
		}

		transportResponseBodyBytes, err := ioutil.ReadAll(transportResponse.Body)
		require.NoError(t, err)
		assert.Equal(t, response.body, string(transportResponseBodyBytes))
	})

	t.Run("should ignore forwarded request if context is not proxyOnlyContext", func(t *testing.T) {
		expectations := serverExpectations{
			method:  http.MethodPost,
			headers: map[string]string{},
			body:    `{"hello":"world"}`,
		}

		response := serverResponse{
			statusCode: http.StatusOK,
			headers: map[string]string{
				http.CanonicalHeaderKey("X-Response-Key"): "response-value",
			},
			body: `{"ping":"pong}"`,
		}

		testServer := newTestServer(t, expectations, response)
		defer testServer.Close()

		forwardedRequest, err := http.NewRequest(http.MethodPut, "http://tyk-gateway:8080", bytes.NewBufferString(`{"ignoredByTransport":true}`))
		require.NoError(t, err)

		forwardedRequest.Header.Set("X-Custom-Key", "custom-value")
		forwardedRequest.Header.Set("X-Other-Value", "other-value")
		ctx := context.Background()

		httpClient := http.Client{
			Transport: NewGraphQLEngineTransport(GraphQLEngineTransportTypeProxyOnly, http.DefaultTransport),
		}

		upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, testServer.URL, bytes.NewBufferString(`{"hello":"world"}`))
		require.NoError(t, err)

		transportResponse, err := httpClient.Do(upstreamRequest)
		assert.Equal(t, response.statusCode, transportResponse.StatusCode)

		for expectedTransportResponseHeaderKey, expectedTransportResponseHeaderValue := range response.headers {
			if assert.Contains(t, transportResponse.Header, expectedTransportResponseHeaderKey) {
				assert.Equal(t, expectedTransportResponseHeaderValue, transportResponse.Header.Get(expectedTransportResponseHeaderKey))
			}
		}

		transportResponseBodyBytes, err := ioutil.ReadAll(transportResponse.Body)
		require.NoError(t, err)
		assert.Equal(t, response.body, string(transportResponseBodyBytes))
	})

	t.Run("should ignore forwarded request if transport type is not proxy only", func(t *testing.T) {
		expectations := serverExpectations{
			method:  http.MethodPost,
			headers: map[string]string{},
			body:    `{"hello":"world"}`,
		}

		response := serverResponse{
			statusCode: http.StatusOK,
			headers: map[string]string{
				http.CanonicalHeaderKey("X-Response-Key"): "response-value",
			},
			body: `{"ping":"pong}"`,
		}

		testServer := newTestServer(t, expectations, response)
		defer testServer.Close()

		forwardedRequest, err := http.NewRequest(http.MethodPut, "http://tyk-gateway:8080", bytes.NewBufferString(`{"ignoredByTransport":true}`))
		require.NoError(t, err)

		forwardedRequest.Header.Set("X-Custom-Key", "custom-value")
		forwardedRequest.Header.Set("X-Other-Value", "other-value")
		ctx := NewGraphQLProxyOnlyContext(context.Background(), forwardedRequest)

		httpClient := http.Client{
			Transport: NewGraphQLEngineTransport(GraphQLEngineTransportTypeMultiUpstream, http.DefaultTransport),
		}

		upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, testServer.URL, bytes.NewBufferString(`{"hello":"world"}`))
		require.NoError(t, err)

		transportResponse, err := httpClient.Do(upstreamRequest)
		assert.Equal(t, response.statusCode, transportResponse.StatusCode)

		for expectedTransportResponseHeaderKey, expectedTransportResponseHeaderValue := range response.headers {
			if assert.Contains(t, transportResponse.Header, expectedTransportResponseHeaderKey) {
				assert.Equal(t, expectedTransportResponseHeaderValue, transportResponse.Header.Get(expectedTransportResponseHeaderKey))
			}
		}

		transportResponseBodyBytes, err := ioutil.ReadAll(transportResponse.Body)
		require.NoError(t, err)
		assert.Equal(t, response.body, string(transportResponseBodyBytes))
	})
}
