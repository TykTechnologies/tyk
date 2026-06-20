package enginev3

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/resolve"
	"github.com/cespare/xxhash/v2"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter/gqlengineadapter"
)

type reqproofEngineV3BadSubscriptionClientFactory struct{}

func (reqproofEngineV3BadSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return reqproofEngineV3BadSubscriptionClient{}
}

type reqproofEngineV3BadSubscriptionClient struct{}

func (reqproofEngineV3BadSubscriptionClient) Subscribe(ctx *resolve.Context, options graphqldatasource.GraphQLSubscriptionOptions, updater resolve.SubscriptionUpdater) error {
	return nil
}

func (reqproofEngineV3BadSubscriptionClient) UniqueRequestID(ctx *resolve.Context, options graphqldatasource.GraphQLSubscriptionOptions, hash *xxhash.Digest) error {
	return nil
}

// Verifies: SYS-REQ-104, SW-REQ-078
// SW-REQ-078:nominal:nominal
// SW-REQ-078:boundary:nominal
// SW-REQ-078:error_handling:nominal
// SW-REQ-078:error_handling:negative
// SW-REQ-078:determinism:nominal
func TestEngineV3GraphQLEngineAdapterUtilitiesPreserveLocalConfigurationBehavior(t *testing.T) {
	require.Nil(t, ConvertApiDefinitionHeadersToHttpHeaders(nil))
	require.Equal(t, http.Header{"X-Trace": {"one"}}, ConvertApiDefinitionHeadersToHttpHeaders(map[string]string{"X-Trace": "one"}))

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
	require.ErrorIs(t, err, gqlengineadapter.ErrGraphQLConfigIsMissingOperation)
	require.Nil(t, restConfig)

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

	urlWithoutParams, queries, err = extractURLQueryParamsForEngineV2("http://rest.example.test/path", nil)
	require.NoError(t, err)
	require.Equal(t, "http://rest.example.test/path", urlWithoutParams)
	require.Nil(t, queries)

	_, _, err = extractURLQueryParamsForEngineV2("http://rest.example.test/path?bad=%zz", nil)
	require.Error(t, err)

	require.Equal(t, graphqldatasource.ProtocolGraphQLWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionUndefined))
	require.Equal(t, graphqldatasource.ProtocolGraphQLWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionWS))
	require.Equal(t, graphqldatasource.ProtocolGraphQLWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionSSE))
	require.Equal(t, graphqldatasource.ProtocolGraphQLTWS, graphqlDataSourceWebSocketProtocol(apidef.GQLSubscriptionTransportWS))

	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	factory, err := createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
		graphqlConfig: apidef.GraphQLEngineDataSourceConfigGraphQL{
			SubscriptionType: apidef.GQLSubscriptionTransportWS,
		},
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
		httpClient:                httpClient,
		streamingClient:           streamingClient,
	})
	require.NoError(t, err)
	require.Same(t, httpClient, factory.HTTPClient)
	require.Same(t, streamingClient, factory.StreamingClient)
	require.NotNil(t, factory.SubscriptionClient)

	factory, err = createGraphQLDataSourceFactory(createGraphQLDataSourceFactoryParams{
		subscriptionClientFactory: reqproofEngineV3BadSubscriptionClientFactory{},
	})
	require.ErrorContains(t, err, "incorrect SubscriptionClient has been created")
	require.Nil(t, factory)
}
