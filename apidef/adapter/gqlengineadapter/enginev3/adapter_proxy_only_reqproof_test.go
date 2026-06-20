package enginev3

import (
	"context"
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

type reqproofEngineV3SubscriptionClientFactory struct{}

func (reqproofEngineV3SubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqldatasource.Options) graphqldatasource.GraphQLSubscriptionClient {
	return &graphqldatasource.SubscriptionClient{}
}

// Verifies: SYS-REQ-104, SW-REQ-076
// SW-REQ-076:nominal:nominal
// SW-REQ-076:boundary:nominal
// SW-REQ-076:error_handling:negative
// SW-REQ-076:determinism:nominal
func TestEngineV3ProxyOnlyEngineConfigPreservesLocalProxyConfiguration(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: `type Query { hello(name: String!): String! }`,
			Proxy: apidef.GraphQLProxyConfig{
				RequestHeaders:   map[string]string{"x-trace": "one"},
				SubscriptionType: apidef.GQLSubscriptionSSE,
			},
		},
		Proxy: apidef.ProxyConfig{
			TargetURL: "tyk://internal-proxy",
		},
	}
	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	adapter := &ProxyOnly{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
	}

	engineConfig, err := adapter.EngineConfigV3()
	require.NoError(t, err)
	require.NotNil(t, adapter.Schema)
	require.Contains(t, engineConfig.FieldConfigurations(), plan.FieldConfiguration{
		TypeName:  "Query",
		FieldName: "hello",
		Arguments: plan.ArgumentsConfigurations{
			{Name: "name", SourceType: plan.FieldArgumentSource},
		},
	})

	dataSources := engineConfig.DataSources()
	require.Len(t, dataSources, 1)
	require.Equal(t, plan.TypeFields{{TypeName: "Query", FieldNames: []string{"hello"}}}, dataSources[0].RootNodes)
	require.Empty(t, dataSources[0].ChildNodes)
	graphQLFactory, ok := dataSources[0].Factory.(*graphqldatasource.Factory)
	require.True(t, ok)
	require.Same(t, httpClient, graphQLFactory.HTTPClient)
	require.Same(t, streamingClient, graphQLFactory.StreamingClient)
	require.NotNil(t, graphQLFactory.SubscriptionClient)
	require.Equal(t, graphqldatasource.ConfigJson(graphqldatasource.Configuration{
		Fetch: graphqldatasource.FetchConfiguration{
			URL: "http://internal-proxy",
			Header: http.Header{
				"X-Trace":        {"one"},
				"X-Tyk-Internal": {"true"},
			},
		},
		Subscription: graphqldatasource.SubscriptionConfiguration{
			URL:    "http://internal-proxy",
			UseSSE: true,
		},
	}), dataSources[0].Custom)

	repeatedAdapter := &ProxyOnly{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
	}
	repeatedConfig, err := repeatedAdapter.EngineConfigV3()
	require.NoError(t, err)
	require.Equal(t, engineConfig.DataSources(), repeatedConfig.DataSources())
	require.Equal(t, engineConfig.FieldConfigurations(), repeatedConfig.FieldConfigurations())

	providedSchemaAdapter := &ProxyOnly{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		Schema:                    adapter.Schema,
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
	}
	providedSchemaAdapter.ApiDefinition.GraphQL.Schema = `type Query { broken: }`
	_, err = providedSchemaAdapter.EngineConfigV3()
	require.NoError(t, err)

	badSchemaAdapter := &ProxyOnly{
		ApiDefinition: &apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{Schema: `type Query { broken: }`},
		},
	}
	badConfig, err := badSchemaAdapter.EngineConfigV3()
	require.Error(t, err)
	require.Nil(t, badConfig)

	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeGraphQLWS), graphqlSubscriptionType(apidef.GQLSubscriptionWS))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeGraphQLTransportWS), graphqlSubscriptionType(apidef.GQLSubscriptionTransportWS))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeSSE), graphqlSubscriptionType(apidef.GQLSubscriptionSSE))
	require.Equal(t, graphql.SubscriptionType(graphql.SubscriptionTypeUnknown), graphqlSubscriptionType(apidef.GQLSubscriptionUndefined))
	require.Equal(t, reqproofEngineV3SubscriptionClientFactory{}, subscriptionClientFactoryOrDefault(reqproofEngineV3SubscriptionClientFactory{}))
	require.IsType(t, &graphqldatasource.DefaultSubscriptionClientFactory{}, subscriptionClientFactoryOrDefault(nil))
}
