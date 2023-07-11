package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/test"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestGraphQLEngineTransport_GlobalHeaders(t *testing.T) {
	initTestServer := func(t *testing.T, expectedHeaders map[string]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			for key, val := range expectedHeaders {
				assert.Equal(t, val, request.Header.Get(key))
			}
		}))
	}

	t.Run("should add all global headers to upstream request", func(t *testing.T) {
		testServer := initTestServer(t, map[string]string{
			"test-global-header":     "header-value",
			"test-datasource-header": "header-value",
		})
		defer testServer.Close()

		testReq, err := http.NewRequest(http.MethodPost, testServer.URL, nil)
		testReq.Header.Set("test-datasource-header", "header-value")
		assert.NoError(t, err)

		client := http.Client{
			Transport: NewGraphQLEngineTransport(GraphQLEngineTransportTypeMultiUpstream, http.DefaultTransport, WithGlobalHeaders(map[string]string{
				"test-global-header": "header-value",
			})),
		}

		_, err = client.Do(testReq)
		assert.NoError(t, err)
	})

	t.Run("should not replace existing global header", func(t *testing.T) {
		testServer := initTestServer(t, map[string]string{
			"test-global-header":     "header-value",
			"test-datasource-header": "datasource-value",
		})
		defer testServer.Close()

		testReq, err := http.NewRequest(http.MethodPost, testServer.URL, nil)
		testReq.Header.Set("test-datasource-header", "datasource-value")
		assert.NoError(t, err)

		client := http.Client{
			Transport: NewGraphQLEngineTransport(GraphQLEngineTransportTypeMultiUpstream, http.DefaultTransport, WithGlobalHeaders(map[string]string{
				"test-global-header":     "header-value",
				"test-datasource-header": "header-value",
			})),
		}

		_, err = client.Do(testReq)
		assert.NoError(t, err)
	})
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
		require.NoError(t, err)
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
		require.NoError(t, err)
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
		require.NoError(t, err)
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

func TestGraphQLEngineTransport_ContextVars(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	customRestUpstreamURL, customGraphQLUpstreamURL := "/custom-rest-upstream", "/custom-graphql-upstream"

	restConfig := apidef.GraphQLEngineDataSourceConfigREST{
		Method: "GET",
		Headers: map[string]string{
			"rest-header": "rest-value",
		},
		URL: TestHttpAny + customRestUpstreamURL,
	}
	restConfigData, err := json.Marshal(restConfig)
	require.NoError(t, err)

	graphQLConfig := apidef.GraphQLEngineDataSourceConfigGraphQL{
		URL:    TestHttpAny + customGraphQLUpstreamURL,
		Method: "POST",
	}
	graphqlConfigData, err := json.Marshal(graphQLConfig)
	require.NoError(t, err)

	spec := BuildAPI(func(spec *APISpec) {
		spec.GraphQL.Enabled = true
		spec.GraphQL.Schema = gqlProxyUpstreamSchema
		spec.EnableContextVars = true
		spec.GraphQL.Version = apidef.GraphQLConfigVersion2
		spec.GraphQL.Engine.FieldConfigs = []apidef.GraphQLFieldConfig{
			{
				TypeName:  "Query",
				FieldName: "hello",
			},
			{
				TypeName:  "Query",
				FieldName: "httpMethod",
			},
		}
		spec.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
			{
				Name:   "Main Rest Datasource",
				Kind:   apidef.GraphQLEngineDataSourceKindREST,
				Config: restConfigData,
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "Query",
						Fields: []string{"httpMethod"},
					},
				},
			},
			{
				Name:   "Main GraphQL Datasource",
				Kind:   apidef.GraphQLEngineDataSourceKindGraphQL,
				Config: graphqlConfigData,
				RootFields: []apidef.GraphQLTypeFields{
					{
						Type:   "Query",
						Fields: []string{"hello"},
					},
				},
			},
		}
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
	})[0]

	t.Run("replace global context vars successfully", func(t *testing.T) {
		spec.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{
			{Key: "global-header", Value: "global-header-value"},
			{Key: "global-header-second", Value: "$tyk_context.headers_Code"},
		}
		g.Gw.LoadAPI(spec)

		receivedHeader := false
		g.AddDynamicHandler(customRestUpstreamURL, func(writer http.ResponseWriter, request *http.Request) {
			headers := request.Header
			if headers.Get("global-header") == "global-header-value" && headers.Get("global-header-second") == "value" {
				receivedHeader = true
			}
		})

		_, err := g.Run(t, test.TestCase{
			Path: "/", Method: "POST",
			Data: gql.Request{
				Query: `{httpMethod}`,
			},
			Headers: map[string]string{
				"code": "value",
			},
			Code: 200,
		})
		assert.NoError(t, err)
		assert.Eventuallyf(t, func() bool {
			return receivedHeader
		}, time.Second, time.Millisecond*100, "headers not sent to upstream")
	})

	t.Run("replace datasource context vars successfully", func(t *testing.T) {
		spec.GraphQL.Engine.GlobalHeaders = []apidef.UDGGlobalHeader{
			{Key: "global-header", Value: "$tyk_context.headers_Second"},
		}
		restConfig.Headers = map[string]string{
			"datasource-header": "$tyk_context.headers_Code",
		}
		restConfigData, err := json.Marshal(restConfig)
		require.NoError(t, err)
		spec.GraphQL.Engine.DataSources[0].Config = restConfigData
		g.Gw.LoadAPI(spec)

		var receivedRestHeader, receivedGQLHeader bool
		g.AddDynamicHandler(customGraphQLUpstreamURL, func(writer http.ResponseWriter, request *http.Request) {
			headers := request.Header
			if headers.Get("global-header") == "second-value" {
				receivedGQLHeader = true
			}
		})
		g.AddDynamicHandler(customRestUpstreamURL, func(writer http.ResponseWriter, request *http.Request) {
			headers := request.Header
			if headers.Get("global-header") == "second-value" && headers.Get("datasource-header") == "value" {
				receivedRestHeader = true
			}
		})

		_, err = g.Run(t, test.TestCase{
			Path: "/", Method: "POST",
			Data: gql.Request{
				Query: `
{
  httpMethod
  hello(name: "Test")
}
`,
			},
			Headers: map[string]string{
				"code":   "value",
				"second": "second-value",
			},
			Code: 200,
		})
		assert.NoError(t, err)

		assert.Eventuallyf(t, func() bool {
			return receivedRestHeader && receivedGQLHeader
		}, time.Second, time.Millisecond*100, "headers not sent to upstream")
	})
}
