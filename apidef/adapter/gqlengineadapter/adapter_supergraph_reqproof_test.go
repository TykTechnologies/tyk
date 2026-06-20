package gqlengineadapter

import (
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-074
// SW-REQ-074:nominal:nominal
// SW-REQ-074:boundary:nominal
// SW-REQ-074:error_handling:negative
// SW-REQ-074:determinism:nominal
func TestSupergraphEngineConfigPreservesLocalSubgraphConfiguration(t *testing.T) {
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
						SSEUsePost:       true,
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
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
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
				URL:           "http://accounts.service",
				UseSSE:        true,
				SSEMethodPost: true,
			},
			Federation: graphqldatasource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: `extend type Query { me: User } type User @key(fields: "id") { id: ID! name: String! }`,
			},
		},
	}, dataSourceConfigs)

	engineConfig, err := adapter.EngineConfig()
	require.NoError(t, err)
	require.Len(t, engineConfig.DataSources(), 1)
	require.IsType(t, &graphqldatasource.Factory{}, engineConfig.DataSources()[0].Factory)
	factory := engineConfig.DataSources()[0].Factory.(*graphqldatasource.Factory)
	require.NotNil(t, factory.BatchFactory)
	require.Same(t, httpClient, factory.HTTPClient)
	require.Same(t, streamingClient, factory.StreamingClient)
	require.NotNil(t, factory.SubscriptionClient)

	repeatedAdapter := &Supergraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	repeatedConfig, err := repeatedAdapter.EngineConfig()
	require.NoError(t, err)
	require.Equal(t, engineConfig.DataSources(), repeatedConfig.DataSources())
	require.Equal(t, engineConfig.FieldConfigurations(), repeatedConfig.FieldConfigurations())

	apiDef.GraphQL.Supergraph.DisableQueryBatching = true
	noBatchConfig, err := adapter.EngineConfig()
	require.NoError(t, err)
	require.Len(t, noBatchConfig.DataSources(), 1)
	noBatchFactory := noBatchConfig.DataSources()[0].Factory.(*graphqldatasource.Factory)
	require.Nil(t, noBatchFactory.BatchFactory)

	apiDef.GraphQL.Supergraph.MergedSDL = `type Query { broken: }`
	badConfig, err := adapter.EngineConfig()
	require.Error(t, err)
	require.Nil(t, badConfig)

	apiDef.GraphQL.Supergraph.Subgraphs = nil
	require.Empty(t, adapter.subgraphDataSourceConfigs())
}
