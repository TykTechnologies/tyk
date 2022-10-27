package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	kafkaDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	restDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLConfigAdapter_EngineConfigV2(t *testing.T) {
	t.Run("should create v2 config for proxy-only mode", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlProxyOnlyConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
			Proxy: apidef.ProxyConfig{
				TargetURL: "http://localhost:8080",
			},
		}

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(apiDef,
			WithHttpClient(httpClient),
			WithStreamingClient(streamingClient),
			withGraphQLSubscriptionClientFactory(&MockSubscriptionClientFactory{}),
		)

		engineV2Config, err := adapter.EngineConfigV2()
		assert.NoError(t, err)

		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"hello"},
				},
			},
			ChildNodes: []plan.TypeField{},
			Factory: &graphqlDataSource.Factory{
				BatchFactory:       graphqlDataSource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL: "http://localhost:8080",
					Header: http.Header{
						"Authorization": []string{"123abc"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://localhost:8080",
					UseSSE: true,
				},
			}),
		}

		expectedFieldConfig := plan.FieldConfiguration{
			TypeName:  "Query",
			FieldName: "hello",
			Arguments: plan.ArgumentsConfigurations{
				{
					Name:       "name",
					SourceType: plan.FieldArgumentSource,
				},
			},
		}

		assert.Containsf(t, engineV2Config.DataSources(), expectedDataSource, "engine configuration does not contain proxy-only data source")
		assert.Containsf(t, engineV2Config.FieldConfigurations(), expectedFieldConfig, "engine configuration does not contain expected field config")
	})

	t.Run("should create v2 config for internal proxy-only api", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlProxyOnlyConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
			Proxy: apidef.ProxyConfig{
				TargetURL: "tyk://api-name",
			},
		}

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(
			apiDef,
			WithHttpClient(httpClient),
			WithStreamingClient(streamingClient),
			withGraphQLSubscriptionClientFactory(&MockSubscriptionClientFactory{}),
		)

		engineV2Config, err := adapter.EngineConfigV2()
		assert.NoError(t, err)

		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"hello"},
				},
			},
			ChildNodes: []plan.TypeField{},
			Factory: &graphqlDataSource.Factory{
				BatchFactory:       graphqlDataSource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL: "http://api-name",
					Header: http.Header{
						"Authorization":  []string{"123abc"},
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://api-name",
					UseSSE: true,
				},
			}),
		}

		expectedFieldConfig := plan.FieldConfiguration{
			TypeName:  "Query",
			FieldName: "hello",
			Arguments: plan.ArgumentsConfigurations{
				{
					Name:       "name",
					SourceType: plan.FieldArgumentSource,
				},
			},
		}

		assert.Containsf(t, engineV2Config.DataSources(), expectedDataSource, "engine configuration does not contain proxy-only data source")
		assert.Containsf(t, engineV2Config.FieldConfigurations(), expectedFieldConfig, "engine configuration does not contain expected field config")
	})

	t.Run("should create v2 config for engine execution mode without error", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		httpClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

		_, err := adapter.EngineConfigV2()
		assert.NoError(t, err)
	})

	t.Run("should create v2 config for supergraph execution mode without error", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		httpClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

		_, err := adapter.EngineConfigV2()
		assert.NoError(t, err)
	})
	t.Run("should create v2 config for supergraph with batching disabled", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}
		apiDef.GraphQL.Supergraph.DisableQueryBatching = true

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(
			apiDef,
			WithHttpClient(httpClient),
			WithStreamingClient(streamingClient),
			withGraphQLSubscriptionClientFactory(&MockSubscriptionClientFactory{}),
		)

		v2Config, err := adapter.EngineConfigV2()
		assert.NoError(t, err)
		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"me"},
				},
				{
					TypeName:   "User",
					FieldNames: []string{"id", "username"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "User",
					FieldNames: []string{"id", "username"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "http://accounts.service",
					Method: http.MethodPost,
					Header: http.Header{
						"Auth":           []string{"appended_header"},
						"Header1":        []string{"override_global"},
						"Header2":        []string{"value2"},
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://accounts.service",
					UseSSE: true,
				},
				Federation: graphqlDataSource.FederationConfiguration{
					Enabled:    true,
					ServiceSDL: `extend type Query {me: User} type User @key(fields: "id"){ id: ID! username: String!}`,
				},
			}),
		}
		assert.Containsf(t, v2Config.DataSources(), expectedDataSource, "engine configuration does not contain proxy-only data source")

	})

	t.Run("should create v2 config for subgraph without error", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlSubgraphConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
			Proxy: apidef.ProxyConfig{
				TargetURL: "http://localhost:8080",
			},
		}

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(
			apiDef,
			WithHttpClient(httpClient),
			WithStreamingClient(streamingClient),
			withGraphQLSubscriptionClientFactory(&MockSubscriptionClientFactory{}),
		)

		engineV2Config, err := adapter.EngineConfigV2()
		assert.NoError(t, err)

		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"me", "_entities", "_service"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "_Service",
					FieldNames: []string{"sdl"},
				},
				{
					TypeName:   "User",
					FieldNames: []string{"id", "username"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				BatchFactory:       graphqlDataSource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL: "http://localhost:8080",
					Header: http.Header{
						"Authorization": []string{"123abc"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://localhost:8080",
					UseSSE: false,
				},
			}),
		}

		expectedFieldConfig := plan.FieldConfiguration{
			TypeName:  "Query",
			FieldName: "_entities",
			Arguments: plan.ArgumentsConfigurations{
				{
					Name:       "representations",
					SourceType: plan.FieldArgumentSource,
				},
			},
		}

		assert.Containsf(t, engineV2Config.DataSources(), expectedDataSource, "engine configuration does not contain proxy-only data source")
		assert.Containsf(t, engineV2Config.FieldConfigurations(), expectedFieldConfig, "engine configuration does not contain expected field config")
	})

	t.Run("should return an error for unsupported config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV1ConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.Error(t, err)
		assert.Equal(t, ErrUnsupportedGraphQLConfigVersion, err)
	})
}

func TestGraphQLConfigAdapter_supergraphDataSourceConfigs(t *testing.T) {
	expectedDataSourceConfigs := []graphqlDataSource.Configuration{
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://accounts.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1":        []string{"override_global"},
					"Header2":        []string{"value2"},
					"X-Tyk-Internal": []string{"true"},
					"Auth":           []string{"appended_header"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL:    "http://accounts.service",
				UseSSE: true,
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationAccountsServiceSDL,
			},
		},
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://products.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1": []string{"value1"},
					"Header2": []string{"value2"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL: "http://products.service",
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationProductsServiceSDL,
			},
		},
		{
			Fetch: graphqlDataSource.FetchConfiguration{
				URL:    "http://reviews.service",
				Method: http.MethodPost,
				Header: http.Header{
					"Header1": []string{"override_global"},
					"Auth":    []string{"appended_header"},
					"Header2": []string{"value2"},
				},
			},
			Subscription: graphqlDataSource.SubscriptionConfiguration{
				URL: "http://reviews.service",
			},
			Federation: graphqlDataSource.FederationConfiguration{
				Enabled:    true,
				ServiceSDL: federationReviewsServiceSDL,
			},
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2SupergraphConfigJson), &gqlConfig))

	apiDef := &apidef.APIDefinition{
		GraphQL: gqlConfig,
	}

	adapter := NewGraphQLConfigAdapter(apiDef)
	actualGraphQLConfigs := adapter.subgraphDataSourceConfigs()
	assert.Equal(t, expectedDataSourceConfigs, actualGraphQLConfigs)
}

func TestGraphQLConfigAdapter_engineConfigV2FieldConfigs(t *testing.T) {
	expectedFieldCfgs := plan.FieldConfigurations{
		{
			TypeName:              "Query",
			FieldName:             "rest",
			DisableDefaultMapping: false,
			Path:                  []string{"my_rest"},
		},
		{
			TypeName:  "Query",
			FieldName: "gql",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "id",
					SourceType: plan.FieldArgumentSource,
				},
				{
					Name:       "name",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
		{
			TypeName:  "Query",
			FieldName: "restWithQueryParams",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "q",
					SourceType: plan.FieldArgumentSource,
				},
				{
					Name:       "order",
					SourceType: plan.FieldArgumentSource,
				},
				{
					Name:       "limit",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
		{
			TypeName:  "Query",
			FieldName: "restWithPathParams",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "id",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
		{
			TypeName:  "Query",
			FieldName: "restWithFullUrlAsParam",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "url",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
		{
			TypeName:  "DeepGQL",
			FieldName: "query",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "code",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
		{
			TypeName:  "Subscription",
			FieldName: "foobarTopicWithVariable",
			Arguments: []plan.ArgumentConfiguration{
				{
					Name:       "name",
					SourceType: plan.FieldArgumentSource,
				},
			},
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

	apiDef := &apidef.APIDefinition{
		GraphQL: gqlConfig,
	}

	adapter := NewGraphQLConfigAdapter(apiDef)
	require.NoError(t, adapter.parseSchema())

	actualFieldCfgs := adapter.engineConfigV2FieldConfigs()
	assert.ElementsMatch(t, expectedFieldCfgs, actualFieldCfgs)
}

func TestGraphQLConfigAdapter_engineConfigV2DataSources(t *testing.T) {
	httpClient := &http.Client{}
	streamingClient := &http.Client{}

	expectedDataSources := []plan.DataSourceConfiguration{
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"rest"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "tyk://rest-example",
					Method: "POST",
					Header: map[string][]string{
						"Authorization": {"123"},
						"X-Custom":      {"A, B"},
					},
					Body: "body",
					Query: []restDataSource.QueryConfiguration{
						{
							Name:  "q",
							Value: "val1,val2",
						},
						{
							Name:  "repeat",
							Value: "val1",
						},
						{
							Name:  "repeat",
							Value: "val2",
						},
					},
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"gql"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "http://graphql-example",
					Method: "POST",
					Header: http.Header{
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "http://graphql-example",
					UseSSE: true,
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"withChildren"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "WithChildren",
					FieldNames: []string{"id", "name", "__typename"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "https://rest.example.com",
					Method: "POST",
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "WithChildren",
					FieldNames: []string{"nested"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "Nested",
					FieldNames: []string{"id", "name", "__typename"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "https://rest.example.com",
					Method: "POST",
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"multiRoot1", "multiRoot2"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "MultiRoot1",
					FieldNames: []string{"id", "__typename"},
				},
				{
					TypeName:   "MultiRoot2",
					FieldNames: []string{"name", "__typename"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: map[string][]string{
						"Auth": {"123"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "https://graphql.example.com",
					UseSSE: false,
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"restWithQueryParams"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "https://rest-with-query-params.example.com",
					Method: "POST",
					Query: []restDataSource.QueryConfiguration{
						{
							Name:  "order",
							Value: "{{.arguments.order}}",
						},
						{
							Name:  "q",
							Value: "{{.arguments.q}}",
						},
						{
							Name:  "limit",
							Value: "{{.arguments.limit}}",
						},
					},
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"restWithPathParams"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "https://rest-with-path-params.example.com/{{.arguments.id}}",
					Method: "POST",
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"restWithFullUrlAsParam"},
				},
			},
			Factory: &restDataSource.Factory{
				Client: httpClient,
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "{{.arguments.url}}",
					Method: "POST",
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"idType"},
				},
			},
			ChildNodes: []plan.TypeField{
				{
					TypeName:   "WithChildren",
					FieldNames: []string{"id", "name", "__typename"},
				},
				{
					TypeName:   "IDType",
					FieldNames: []string{"id", "__typename"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: map[string][]string{
						"Auth": {"123"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL:    "https://graphql.example.com",
					UseSSE: false,
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Subscription",
					FieldNames: []string{"foobar"},
				},
			},
			Factory: &kafkaDataSource.Factory{},
			Custom: kafkaDataSource.ConfigJSON(kafkaDataSource.Configuration{
				Subscription: kafkaDataSource.SubscriptionConfiguration{
					BrokerAddresses:      []string{"localhost:9092"},
					Topics:               []string{"test.topic"},
					GroupID:              "test.consumer.group",
					ClientID:             "test.client.id",
					KafkaVersion:         "V2_8_0_0",
					StartConsumingLatest: true,
					BalanceStrategy:      kafkaDataSource.BalanceStrategySticky,
					IsolationLevel:       kafkaDataSource.IsolationLevelReadCommitted,
					SASL: kafkaDataSource.SASL{
						Enable:   true,
						User:     "admin",
						Password: "admin-secret",
					},
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Subscription",
					FieldNames: []string{"foobarTopicWithVariable"},
				},
			},
			Factory: &kafkaDataSource.Factory{},
			Custom: kafkaDataSource.ConfigJSON(kafkaDataSource.Configuration{
				Subscription: kafkaDataSource.SubscriptionConfiguration{
					BrokerAddresses:      []string{"localhost:9092"},
					Topics:               []string{"test.topic.{{.arguments.name}}"},
					GroupID:              "test.consumer.group",
					ClientID:             "test.client.id",
					KafkaVersion:         "V2_8_0_0",
					StartConsumingLatest: true,
					BalanceStrategy:      kafkaDataSource.BalanceStrategySticky,
					IsolationLevel:       kafkaDataSource.IsolationLevelReadCommitted,
					SASL: kafkaDataSource.SASL{
						Enable:   true,
						User:     "admin",
						Password: "admin-secret",
					},
				},
			}),
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

	apiDef := &apidef.APIDefinition{
		GraphQL: gqlConfig,
	}

	adapter := NewGraphQLConfigAdapter(
		apiDef, WithHttpClient(httpClient),
		WithStreamingClient(streamingClient),
		withGraphQLSubscriptionClientFactory(&MockSubscriptionClientFactory{}),
	)
	require.NoError(t, adapter.parseSchema())

	actualDataSources, err := adapter.engineConfigV2DataSources()
	assert.NoError(t, err)
	assert.Equal(t, expectedDataSources, actualDataSources)
	//assert.ElementsMatch(t, expectedDataSources, actualDataSources)
}

func TestGraphQLConfigAdapter_GraphqlDataSourceWebSocketProtocol(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedWebSocketProtocol string) func(t *testing.T) {
		return func(t *testing.T) {
			adapter := NewGraphQLConfigAdapter(nil)
			actualProtocol := adapter.graphqlDataSourceWebSocketProtocol(subscriptionType)
			assert.Equal(t, expectedWebSocketProtocol, actualProtocol)
		}
	}

	t.Run("should return 'graphql-ws' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-ws' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphqlDataSource.ProtocolGraphQLWS),
	)

	t.Run("should return 'graphql-transport-ws' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphqlDataSource.ProtocolGraphQLTWS),
	)
}

func TestGraphQLConfigAdapter_GraphqlSubscriptionType(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedGraphQLSubscriptionType graphql.SubscriptionType) func(t *testing.T) {
		return func(t *testing.T) {
			adapter := NewGraphQLConfigAdapter(nil)
			actualSubscriptionType := adapter.graphqlSubscriptionType(subscriptionType)
			assert.Equal(t, expectedGraphQLSubscriptionType, actualSubscriptionType)
		}
	}

	t.Run("should return 'Unknown' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphql.SubscriptionTypeUnknown),
	)

	t.Run("should return 'SSE' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphql.SubscriptionTypeSSE),
	)

	t.Run("should return 'GraphQLWS' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphql.SubscriptionTypeGraphQLWS),
	)

	t.Run("should return 'GraphQLTransportWS' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphql.SubscriptionTypeGraphQLTransportWS),
	)
}

var mockSubscriptionClient = &graphqlDataSource.SubscriptionClient{}

type MockSubscriptionClientFactory struct{}

func (m *MockSubscriptionClientFactory) NewSubscriptionClient(httpClient, streamingClient *http.Client, engineCtx context.Context, options ...graphqlDataSource.Options) graphqlDataSource.GraphQLSubscriptionClient {
	return mockSubscriptionClient
}

const graphqlEngineV1ConfigJson = `{
	"enabled": true,
	"execution_mode": "executionEngine",
	"schema": "type Query { rest: String, gql: String }",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"playground": {}
}`

var v2Schema = strconv.Quote(`type Query {
  rest: String
  gql(id: ID!, name: String): String
  deepGQL: DeepGQL
  withChildren: WithChildren
  multiRoot1: MultiRoot1
  multiRoot2: MultiRoot2
  restWithQueryParams(q: String, order: String, limit: Int): [String]
  restWithPathParams(id: String): [String]
  restWithFullUrlAsParam(url: String): [String]
  idType: IDType!
}
interface IDType {
	id: ID!
}
type WithChildren implements IDType {
  id: ID!
  name: String
  nested: Nested
}
type Nested {
  id: ID!
  name: String!
}
type MultiRoot1 {
  id: ID!
}
type MultiRoot2 {
  name: String!
}
type DeepGQL {
  query(code: String!): String
}
type Subscription {
  foobar: Int
  foobarTopicWithVariable(name: String): Int
}`)

var graphqlEngineV2ConfigJson = `{
	"enabled": true,
	"execution_mode": "executionEngine",
	"version": "2",
	"schema": ` + v2Schema + `,
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"engine": {
		"field_configs": [
			{
				"type_name": "Query",
				"field_name": "rest",
				"disable_default_mapping": false,
				"path": ["my_rest"]
			}
		],
		"data_sources": [
		   {
				"kind": "REST",
				"name": "",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["rest"] }
				],
				"config": {
					"url": "tyk://rest-example",
					"method": "POST",
					"headers": {
						"Authorization": "123",
						"X-Custom": "A, B"
					},
					"query": [
						{
							"name": "q",
							"value": "val1,val2"
						},
						{
							"name": "repeat",
							"value": "val1"
						},
						{
							"name": "repeat",
							"value": "val2"
						}
					],
					"body": "body"
				}
			},
			{
				"kind": "GraphQL",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["gql"] }
				],
				"config": {
					"url": "tyk://graphql-example",
					"method": "POST",
					"subscription_type": "sse"
				}
			},
		   	{
				"kind": "REST",
				"name": "",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["withChildren"] }
				],
				"config": {
					"url": "https://rest.example.com",
					"method": "POST",
					"headers": {},
					"query": [],
					"body": ""
				}
			},
		   	{
				"kind": "REST",
				"name": "",
				"internal": true,
				"root_fields": [
					{ "type": "WithChildren", "fields": ["nested"] }
				],
				"config": {
					"url": "https://rest.example.com",
					"method": "POST",
					"headers": {},
					"query": [],
					"body": ""
				}
			},
			{
				"kind": "GraphQL",
				"internal": false,
				"root_fields": [
					{ "type": "Query", "fields": ["multiRoot1","multiRoot2"] }
				],
				"config": {
					"url": "https://graphql.example.com",
					"method": "POST",
					"headers": {
						"Auth": "123"
					}
				}
			},
			{
				"kind": "REST",
				"name": "restWithQueryParams",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["restWithQueryParams"] }
				],
				"config": {
					"url": "https://rest-with-query-params.example.com?q={{.arguments.q}}&order={{.arguments.order}}",
					"method": "POST",
					"headers": {},
					"query": [
						{
							"name": "limit",
							"value": "{{.arguments.limit}}"
						}
					],
					"body": ""
				}
			},
			{
				"kind": "REST",
				"name": "restWithPathParams",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["restWithPathParams"] }
				],
				"config": {
					"url": "https://rest-with-path-params.example.com/{{.arguments.id}}",
					"method": "POST",
					"headers": {},
					"query": [],
					"body": ""
				}
			},
			{
				"kind": "REST",
				"name": "restWithFullUrlAsParam",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["restWithFullUrlAsParam"] }
				],
				"config": {
					"url": "{{.arguments.url}}",
					"method": "POST",
					"headers": {},
					"query": [],
					"body": ""
				}
			},
			{
				"kind": "GraphQL",
				"internal": false,
				"root_fields": [
					{ "type": "Query", "fields": ["idType"] }
				],
				"config": {
					"url": "https://graphql.example.com",
					"method": "POST",
					"headers": {
						"Auth": "123"
					}
				}
			},
			{
				"kind": "Kafka",
				"name": "kafka-consumer-group",
				"internal": false,
				"root_fields": [{
					"type": "Subscription",
					"fields": [
						"foobar"
					]
				}],
				"config": {
					"broker_addresses": ["localhost:9092"],
					"topics": ["test.topic"],
					"group_id": "test.consumer.group",
					"client_id": "test.client.id",
					"kafka_version": "V2_8_0_0",
					"start_consuming_latest": true,
					"balance_strategy": "BalanceStrategySticky",
					"isolation_level": "ReadCommitted",
					"sasl": {
						"enable": true,
						"user": "admin",
						"password": "admin-secret"
					}
				}
			},
			{
				"kind": "Kafka",
				"name": "kafka-consumer-group-with-variable",
				"internal": false,
				"root_fields": [{
					"type": "Subscription",
					"fields": [
						"foobarTopicWithVariable"
					]
				}],
				"config": {
					"broker_addresses": ["localhost:9092"],
					"topics": ["test.topic.{{.arguments.name}}"],
					"group_id": "test.consumer.group",
					"client_id": "test.client.id",
					"kafka_version": "V2_8_0_0",
					"start_consuming_latest": true,
					"balance_strategy": "BalanceStrategySticky",
					"isolation_level": "ReadCommitted",
					"sasl": {
						"enable": true,
						"user": "admin",
						"password": "admin-secret"
					}
				}
			}
		]
	},
	"playground": {}
}`

const federationAccountsServiceSDL = `extend type Query {me: User} type User @key(fields: "id"){ id: ID! username: String!}`
const federationProductsServiceSDL = `extend type Query {topProducts(first: Int = 5): [Product]} type Product @key(fields: "upc") {upc: String! name: String! price: Int!}`
const federationReviewsServiceSDL = `type Review { body: String! author: User! @provides(fields: "username") product: Product! } extend type User @key(fields: "id") { id: ID! @external reviews: [Review] } extend type Product @key(fields: "upc") { upc: String! @external reviews: [Review] }`
const federationMergedSDL = `type Query { me: User topProducts(first: Int = 5): [Product] } type User { id: ID! username: String! reviews: [Review] } type Product { upc: String! name: String! price: Int! reviews: [Review] } type Review { body: String! author: User! product: Product! }`

var graphqlEngineV2SupergraphConfigJson = `{
	"enabled": true,
	"execution_mode": "supergraph",
	"version": "2",
	"schema": "",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"engine": {
		"field_configs": [],
		"data_sources": []
	},
	"supergraph": {
		"subgraphs": [
			{
				"api_id": "",
				"url": "tyk://accounts.service",
				"sdl": ` + strconv.Quote(federationAccountsServiceSDL) + `,
				"headers": {
					"header1": "override_global",
					"Auth": "appended_header"
				},
				"subscription_type": "sse"
			},
			{
				"api_id": "",
				"url": "http://products.service",
				"sdl": ` + strconv.Quote(federationProductsServiceSDL) + `
			},
			{
				"api_id": "",
				"url": "http://ignored.service",
				"sdl": ""
			},
			{
				"api_id": "",
				"url": "http://reviews.service",
				"sdl": ` + strconv.Quote(federationReviewsServiceSDL) + `,
				"headers": {
					"header1": "override_global",
					"header2": "value2",
					"Auth": "appended_header"
				}
			}
		],
		"global_headers": {
			"header1": "value1",
			"header2": "value2"
		},
		"merged_sdl": "` + federationMergedSDL + `"
	},
	"playground": {}
}`

var graphqlProxyOnlyConfig = `{
	"enabled": true,
	"execution_mode": "proxyOnly",
	"version": "2",
	"schema": "type Query { hello(name: String!): String! }",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"proxy": {
		"auth_headers": {
			"Authorization": "123abc"
		},
		"subscription_type": "sse"
	},
	"engine": {
		"field_configs": [],
		"data_sources": []
	},
	"supergraph": {
		"subgraphs": [],
		"global_headers": {},
		"merged_sdl": ""
	},
	"playground": {}
}`

var graphqlSubgraphConfig = `{
	"enabled": true,
	"execution_mode": "subgraph",
	"version": "2",
	"schema": ` + strconv.Quote(graphqlSubgraphSchema) + `,
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"proxy": {
		"auth_headers": {
			"Authorization": "123abc"
		}
	},
	"engine": {
		"field_configs": [],
		"data_sources": []
	},
	"subgraph": {
		"sdl": ` + strconv.Quote(federationAccountsServiceSDL) + `,
		"subscription_type": "graphql-transport-ws"
	},
	"playground": {}
}`

const graphqlSubgraphSchema = `scalar _Any scalar _FieldSet union _Entity = User type _Service { sdl: String } type Query { me: User _entities(representations: [_Any!]!): [_Entity]! _service: _Service! } type User { id: ID! username: String! }`
