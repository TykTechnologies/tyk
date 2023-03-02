package adapter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlDataSource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"

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
					URL:    "http://localhost:8080",
					Header: map[string][]string{},
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
					URL:    "http://localhost:8080",
					Header: http.Header{},
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
