package gqlengineadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

type reqproofSubscriptionClientFactory struct{}

func (reqproofSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return &graphqldatasource.SubscriptionClient{}
}

type reqproofBadSubscriptionClientFactory struct{}

func (reqproofBadSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return reqproofBadSubscriptionClient{}
}

type reqproofBadSubscriptionClient struct{}

func (reqproofBadSubscriptionClient) Subscribe(ctx context.Context, options graphqldatasource.GraphQLSubscriptionOptions, next chan<- []byte) error {
	return nil
}

// Verifies: SYS-REQ-104, SW-REQ-072
// SW-REQ-072:nominal:nominal
// SW-REQ-072:boundary:nominal
// SW-REQ-072:error_handling:nominal
// SW-REQ-072:error_handling:negative
// SW-REQ-072:determinism:nominal
func TestGraphQLEngineAdapterUtilitiesPreserveLocalConfigurationBehavior(t *testing.T) {
	parsedSchema, err := parseSchema(`type Query { hello: String! }`)
	require.NoError(t, err)
	require.NotNil(t, parsedSchema)

	_, err = parseSchema(`type Query { hello: }`)
	require.Error(t, err)

	require.Equal(t, graphqldatasource.ProtocolGraphQLWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionUndefined))
	require.Equal(t, graphqldatasource.ProtocolGraphQLTWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionTransportWS))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeGraphQLWS), graphqlSubscriptionType(apidef.GQLSubscriptionWS))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeSSE), graphqlSubscriptionType(apidef.GQLSubscriptionSSE))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeUnknown), graphqlSubscriptionType(apidef.GQLSubscriptionUndefined))

	require.Nil(t, ConvertApiDefinitionHeadersToHttpHeaders(nil))
	require.Equal(t, http.Header{"X-Trace": {"one"}}, ConvertApiDefinitionHeadersToHttpHeaders(map[string]string{"X-Trace": "one"}))
	require.Equal(t, map[string]string{
		"Authorization": "first",
		"X-Tyk-Key":     "second",
	}, RemoveDuplicateApiDefinitionHeaders(
		map[string]string{"authorization": "first"},
		map[string]string{"Authorization": "second", "x-tyk-key": "second"},
	))

	restConfig, err := generateRestDataSourceFromGraphql(apidef.GraphQLEngineDataSourceConfigGraphQL{
		URL:          "http://graphql.example.test",
		Method:       http.MethodPost,
		Headers:      map[string]string{"x-header": "value"},
		HasOperation: true,
		Operation:    "query Find { item }",
		Variables:    json.RawMessage(`{"id":"123"}`),
	})
	require.NoError(t, err)
	require.Equal(t, restdatasource.ConfigJSON(restdatasource.Configuration{
		Fetch: restdatasource.FetchConfiguration{
			URL:    "http://graphql.example.test",
			Method: http.MethodPost,
			Body:   `{"variables":{"id":"123"},"query":"query Find { item }"}`,
			Header: http.Header{"X-Header": {"value"}},
		},
	}), restConfig)

	restConfig, err = generateRestDataSourceFromGraphql(apidef.GraphQLEngineDataSourceConfigGraphQL{})
	require.ErrorIs(t, err, ErrGraphQLConfigIsMissingOperation)
	require.Nil(t, restConfig)

	graphQLConfig := graphqlDataSourceConfiguration(
		"tyk://internal.example.test/graphql",
		http.MethodGet,
		map[string]string{"authorization": "token"},
		apidef.GQLSubscriptionSSE,
		true,
	)
	require.Equal(t, "http://internal.example.test/graphql", graphQLConfig.Fetch.URL)
	require.Equal(t, http.Header{
		"Authorization": {"token"},
		http.CanonicalHeaderKey(apidef.TykInternalApiHeader): {"true"},
	}, graphQLConfig.Fetch.Header)
	require.Equal(t, "http://internal.example.test/graphql", graphQLConfig.Subscription.URL)
	require.True(t, graphQLConfig.Subscription.UseSSE)
	require.True(t, graphQLConfig.Subscription.SSEMethodPost)

	require.Equal(t, plan.ArgumentsConfigurations{
		{Name: "first", SourceType: plan.FieldArgumentSource},
		{Name: "second", SourceType: plan.FieldArgumentSource},
	}, createArgumentConfigurationsForArgumentNames("first", "second"))

	urlWithoutParams, queries, err := extractURLQueryParamsForEngineV2(
		"http://rest.example.test/path?b=2&a=1&a=3",
		[]apidef.QueryVariable{{Name: "provided", Value: "{{.arguments.provided}}"}},
	)
	require.NoError(t, err)
	require.Equal(t, "http://rest.example.test/path", urlWithoutParams)
	require.Equal(t, []restdatasource.QueryConfiguration{
		{Name: "a", Value: "1,3"},
		{Name: "b", Value: "2"},
		{Name: "provided", Value: "{{.arguments.provided}}"},
	}, queries)

	_, _, err = extractURLQueryParamsForEngineV2("http://rest.example.test/path?bad=%zz", nil)
	require.Error(t, err)

	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	factory, err := createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
		graphqlConfig: apidef.GraphQLEngineDataSourceConfigGraphQL{
			SubscriptionType: apidef.GQLSubscriptionTransportWS,
		},
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
		httpClient:                httpClient,
		streamingClient:           streamingClient,
	})
	require.NoError(t, err)
	require.Same(t, httpClient, factory.HTTPClient)
	require.Same(t, streamingClient, factory.StreamingClient)
	require.NotNil(t, factory.SubscriptionClient)

	factory, err = createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
		subscriptionClientFactory: reqproofBadSubscriptionClientFactory{},
	})
	require.ErrorContains(t, err, "incorrect SubscriptionClient has been created")
	require.Nil(t, factory)

	providedFactory := reqproofSubscriptionClientFactory{}
	require.Equal(t, providedFactory, subscriptionClientFactoryOrDefault(providedFactory))
	require.IsType(t, &graphqldatasource.DefaultSubscriptionClientFactory{}, subscriptionClientFactoryOrDefault(nil))
}
