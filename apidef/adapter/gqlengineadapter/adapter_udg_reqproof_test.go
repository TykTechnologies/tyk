package gqlengineadapter

import (
	"encoding/json"
	"net/http"
	"testing"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-075
// SW-REQ-075:nominal:nominal
// SW-REQ-075:boundary:nominal
// SW-REQ-075:error_handling:nominal
// SW-REQ-075:error_handling:negative
// SW-REQ-075:determinism:nominal
func TestUniversalDataGraphEngineConfigPreservesLocalDatasourceConfiguration(t *testing.T) {
	apiDef := reqproofUDGAPIDefinition(t)
	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	adapter := &UniversalDataGraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}

	engineConfig, err := adapter.EngineConfig()
	require.NoError(t, err)
	require.NotNil(t, adapter.Schema)
	require.ElementsMatch(t, plan.FieldConfigurations{
		{
			TypeName:              "Query",
			FieldName:             "restSearch",
			DisableDefaultMapping: true,
			Path:                  []string{"payload", "items"},
			Arguments: []plan.ArgumentConfiguration{
				{Name: "term", SourceType: plan.FieldArgumentSource},
				{Name: "limit", SourceType: plan.FieldArgumentSource},
			},
		},
		{
			TypeName:  "Query",
			FieldName: "graphItem",
			Arguments: []plan.ArgumentConfiguration{
				{Name: "id", SourceType: plan.FieldArgumentSource},
			},
		},
		{
			TypeName:  "Query",
			FieldName: "graphAsRest",
			Arguments: []plan.ArgumentConfiguration{
				{Name: "id", SourceType: plan.FieldArgumentSource},
			},
		},
		{
			TypeName:  "Subscription",
			FieldName: "topicEvents",
			Arguments: []plan.ArgumentConfiguration{
				{Name: "topic", SourceType: plan.FieldArgumentSource},
			},
		},
	}, engineConfig.FieldConfigurations())

	dataSources := engineConfig.DataSources()
	require.Len(t, dataSources, 4)

	require.Equal(t, []plan.TypeField{{TypeName: "Query", FieldNames: []string{"restSearch"}}}, dataSources[0].RootNodes)
	require.Equal(t, &restdatasource.Factory{Client: httpClient}, dataSources[0].Factory)
	require.Equal(t, restdatasource.ConfigJSON(restdatasource.Configuration{
		Fetch: restdatasource.FetchConfiguration{
			URL:    "https://rest.example.test/search",
			Method: http.MethodPost,
			Header: http.Header{"X-Rest": {"rest"}},
			Query: []restdatasource.QueryConfiguration{
				{Name: "existing", Value: "1"},
				{Name: "repeat", Value: "a,b"},
				{Name: "term", Value: "{{.arguments.term}}"},
			},
			Body: `{"limit":"{{.arguments.limit}}"}`,
		},
	}), dataSources[0].Custom)

	require.Equal(t, []plan.TypeField{{TypeName: "Query", FieldNames: []string{"graphItem"}}}, dataSources[1].RootNodes)
	require.Contains(t, dataSources[1].ChildNodes, plan.TypeField{TypeName: "Item", FieldNames: []string{"id", "name", "__typename"}})
	graphQLFactory, ok := dataSources[1].Factory.(*graphqldatasource.Factory)
	require.True(t, ok)
	require.Same(t, httpClient, graphQLFactory.HTTPClient)
	require.Same(t, streamingClient, graphQLFactory.StreamingClient)
	require.NotNil(t, graphQLFactory.SubscriptionClient)
	require.Equal(t, graphqldatasource.ConfigJson(graphqldatasource.Configuration{
		Fetch: graphqldatasource.FetchConfiguration{
			URL:    "http://graphql.internal.test/query",
			Method: http.MethodPost,
			Header: http.Header{
				"X-Graphql":      {"graphql"},
				"X-Tyk-Internal": {"true"},
			},
		},
		Subscription: graphqldatasource.SubscriptionConfiguration{
			URL:           "http://graphql.internal.test/query",
			UseSSE:        true,
			SSEMethodPost: true,
		},
	}), dataSources[1].Custom)

	require.Equal(t, []plan.TypeField{{TypeName: "Query", FieldNames: []string{"graphAsRest"}}}, dataSources[2].RootNodes)
	require.Equal(t, &restdatasource.Factory{Client: httpClient}, dataSources[2].Factory)
	require.Equal(t, restdatasource.ConfigJSON(restdatasource.Configuration{
		Fetch: restdatasource.FetchConfiguration{
			URL:    "https://graphql-as-rest.example.test/query",
			Method: http.MethodPost,
			Header: http.Header{"X-Operation": {"rest"}},
			Body:   `{"variables":{"id":"{{.arguments.id}}"},"query":"query($id: ID!) { graphItem(id: $id) { id } }"}`,
		},
	}), dataSources[2].Custom)

	require.Equal(t, []plan.TypeField{{TypeName: "Subscription", FieldNames: []string{"topicEvents"}}}, dataSources[3].RootNodes)
	require.Equal(t, &kafkadatasource.Factory{}, dataSources[3].Factory)
	require.Equal(t, kafkadatasource.ConfigJSON(kafkadatasource.Configuration{
		Subscription: kafkadatasource.SubscriptionConfiguration{
			BrokerAddresses:      []string{"localhost:9092"},
			Topics:               []string{"events.{{.arguments.topic}}"},
			GroupID:              "reqproof.group",
			ClientID:             "reqproof.client",
			KafkaVersion:         "V2_8_0_0",
			StartConsumingLatest: true,
			BalanceStrategy:      kafkadatasource.BalanceStrategySticky,
			IsolationLevel:       kafkadatasource.IsolationLevelReadCommitted,
			SASL: kafkadatasource.SASL{
				Enable:   true,
				User:     "user",
				Password: "pass",
			},
		},
	}), dataSources[3].Custom)

	repeatedAdapter := &UniversalDataGraph{
		ApiDefinition:             reqproofUDGAPIDefinition(t),
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	repeatedConfig, err := repeatedAdapter.EngineConfig()
	require.NoError(t, err)
	require.Equal(t, engineConfig.DataSources(), repeatedConfig.DataSources())
	require.ElementsMatch(t, engineConfig.FieldConfigurations(), repeatedConfig.FieldConfigurations())

	providedSchemaAdapter := &UniversalDataGraph{
		ApiDefinition:             reqproofUDGAPIDefinition(t),
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		Schema:                    adapter.Schema,
		subscriptionClientFactory: reqproofSubscriptionClientFactory{},
	}
	providedSchemaAdapter.ApiDefinition.GraphQL.Schema = `type Query { broken: }`
	_, err = providedSchemaAdapter.EngineConfig()
	require.NoError(t, err)

	badSchemaAdapter := &UniversalDataGraph{
		ApiDefinition: &apidef.APIDefinition{GraphQL: apidef.GraphQLConfig{Schema: `type Query { broken: }`}},
	}
	badConfig, err := badSchemaAdapter.EngineConfig()
	require.Error(t, err)
	require.Nil(t, badConfig)

	badRESTAdapter := &UniversalDataGraph{
		ApiDefinition: reqproofUDGAPIDefinition(t),
		Schema:        adapter.Schema,
	}
	badRESTAdapter.ApiDefinition.GraphQL.Engine.DataSources = []apidef.GraphQLEngineDataSource{
		{
			Kind:       apidef.GraphQLEngineDataSourceKindREST,
			RootFields: []apidef.GraphQLTypeFields{{Type: "Query", Fields: []string{"restSearch"}}},
			Config:     json.RawMessage(`{"url":"https://rest.example.test/path?bad=%zz","method":"GET"}`),
		},
	}
	badDataSources, err := badRESTAdapter.engineConfigV2DataSources()
	require.Error(t, err)
	require.Nil(t, badDataSources)
}

func reqproofUDGAPIDefinition(t *testing.T) *apidef.APIDefinition {
	t.Helper()

	return &apidef.APIDefinition{
		GraphQL: apidef.GraphQLConfig{
			Schema: `type Query {
  restSearch(term: String!, limit: Int): [Item]
  graphItem(id: ID!): Item
  graphAsRest(id: ID!): String
}
type Item {
  id: ID!
  name: String!
}
type Subscription {
  topicEvents(topic: String!): Int
}`,
			Engine: apidef.GraphQLEngineConfig{
				FieldConfigs: []apidef.GraphQLFieldConfig{
					{
						TypeName:              "Query",
						FieldName:             "restSearch",
						DisableDefaultMapping: true,
						Path:                  []string{"payload", "items"},
					},
				},
				DataSources: []apidef.GraphQLEngineDataSource{
					{
						Kind:       apidef.GraphQLEngineDataSourceKindREST,
						RootFields: []apidef.GraphQLTypeFields{{Type: "Query", Fields: []string{"restSearch"}}},
						Config: reqproofRawJSON(t, apidef.GraphQLEngineDataSourceConfigREST{
							URL:     "https://rest.example.test/search?existing=1&repeat=a&repeat=b",
							Method:  http.MethodPost,
							Headers: map[string]string{"x-rest": "rest"},
							Query: []apidef.QueryVariable{
								{Name: "term", Value: "{{.arguments.term}}"},
							},
							Body: `{"limit":"{{.arguments.limit}}"}`,
						}),
					},
					{
						Kind:       apidef.GraphQLEngineDataSourceKindGraphQL,
						RootFields: []apidef.GraphQLTypeFields{{Type: "Query", Fields: []string{"graphItem"}}},
						Config: reqproofRawJSON(t, apidef.GraphQLEngineDataSourceConfigGraphQL{
							URL:              "tyk://graphql.internal.test/query",
							Method:           http.MethodPost,
							Headers:          map[string]string{"x-graphql": "graphql"},
							SubscriptionType: apidef.GQLSubscriptionSSE,
							SSEUsePost:       true,
						}),
					},
					{
						Kind:       apidef.GraphQLEngineDataSourceKindGraphQL,
						RootFields: []apidef.GraphQLTypeFields{{Type: "Query", Fields: []string{"graphAsRest"}}},
						Config: reqproofRawJSON(t, apidef.GraphQLEngineDataSourceConfigGraphQL{
							URL:          "https://graphql-as-rest.example.test/query",
							Method:       http.MethodPost,
							Headers:      map[string]string{"x-operation": "rest"},
							HasOperation: true,
							Operation:    `query($id: ID!) { graphItem(id: $id) { id } }`,
							Variables:    json.RawMessage(`{"id":"{{.arguments.id}}"}`),
						}),
					},
					{
						Kind:       apidef.GraphQLEngineDataSourceKindKafka,
						RootFields: []apidef.GraphQLTypeFields{{Type: "Subscription", Fields: []string{"topicEvents"}}},
						Config: reqproofRawJSON(t, apidef.GraphQLEngineDataSourceConfigKafka{
							BrokerAddresses:      []string{"localhost:9092"},
							Topics:               []string{"events.{{.arguments.topic}}"},
							GroupID:              "reqproof.group",
							ClientID:             "reqproof.client",
							KafkaVersion:         "V2_8_0_0",
							StartConsumingLatest: true,
							BalanceStrategy:      string(kafkadatasource.BalanceStrategySticky),
							IsolationLevel:       string(kafkadatasource.IsolationLevelReadCommitted),
							SASL: apidef.GraphQLEngineKafkaSASL{
								Enable:   true,
								User:     "user",
								Password: "pass",
							},
						}),
					},
				},
			},
		},
	}
}

func reqproofRawJSON(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()

	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}
