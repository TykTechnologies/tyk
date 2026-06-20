package enginev3

import (
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-077
// SW-REQ-077:nominal:nominal
// SW-REQ-077:boundary:nominal
// SW-REQ-077:error_handling:nominal
// SW-REQ-077:error_handling:negative
// SW-REQ-077:determinism:nominal
func TestEngineV3SupergraphEngineConfigPreservesLocalSubgraphConfiguration(t *testing.T) {
	apiDef := &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Supergraph: apidef.GraphQLSupergraphConfig{
				GlobalHeaders: map[string]string{
					"x-global": "global",
					"x-shared": "global",
				},
				MergedSDL: `type Query { me: User } type User { id: ID! name: String! }`,
				Subgraphs: []apidef.GraphQLSubgraphEntity{
					{
						URL:              "tyk://accounts.service",
						SDL:              `extend type Query { me: User } type User @key(fields: "id") { id: ID! name: String! }`,
						Headers:          map[string]string{"x-shared": "local", "x-local": "accounts"},
						SubscriptionType: apidef.GQLSubscriptionSSE,
					},
					{
						URL: "http://ignored.service",
						SDL: "",
					},
				},
			},
		},
	}
	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	adapter := &Supergraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
	}

	dataSourceConfigs := adapter.subgraphDataSourceConfigs()
	require.Equal(t, []graphqldatasource.Configuration{
		{
			Fetch: graphqldatasource.FetchConfiguration{
				URL:    "http://accounts.service",
				Method: http.MethodPost,
				Header: http.Header{
					"X-Global":       {"global"},
					"X-Local":        {"accounts"},
					"X-Shared":       {"local"},
					"X-Tyk-Internal": {"true"},
				},
			},
			Subscription: graphqldatasource.SubscriptionConfiguration{
				URL:    "http://accounts.service",
				UseSSE: true,
			},
			Federation: graphqldatasource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: `extend type Query { me: User } type User @key(fields: "id") { id: ID! name: String! }`,
			},
		},
	}, dataSourceConfigs)

	engineConfig, err := adapter.EngineConfigV3()
	require.NoError(t, err)
	require.Len(t, engineConfig.DataSources(), 1)
	graphQLFactory, ok := engineConfig.DataSources()[0].Factory.(*graphqldatasource.Factory)
	require.True(t, ok)
	require.Same(t, httpClient, graphQLFactory.HTTPClient)
	require.Same(t, streamingClient, graphQLFactory.StreamingClient)
	require.NotNil(t, graphQLFactory.SubscriptionClient)

	repeatedAdapter := &Supergraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofEngineV3SubscriptionClientFactory{},
	}
	repeatedConfig, err := repeatedAdapter.EngineConfigV3()
	require.NoError(t, err)
	require.Equal(t, engineConfig.DataSources(), repeatedConfig.DataSources())
	require.Equal(t, engineConfig.FieldConfigurations(), repeatedConfig.FieldConfigurations())

	apiDef.GraphQL.Supergraph.MergedSDL = `type Query { broken: }`
	badConfig, err := adapter.EngineConfigV3()
	require.Error(t, err)
	require.Nil(t, badConfig)

	apiDef.GraphQL.Supergraph.Subgraphs = nil
	require.Empty(t, adapter.subgraphDataSourceConfigs())
}
