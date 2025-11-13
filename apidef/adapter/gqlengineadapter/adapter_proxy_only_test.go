package gqlengineadapter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/plan"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestProxyOnly_EngineConfig(t *testing.T) {
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
		adapter := ProxyOnly{
			ApiDefinition:             apiDef,
			HttpClient:                httpClient,
			StreamingClient:           streamingClient,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		engineV2Config, err := adapter.EngineConfig()
		assert.NoError(t, err)

		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"hello"},
				},
			},
			ChildNodes: []plan.TypeField{},
			Factory: &graphqldatasource.Factory{
				BatchFactory:       graphqldatasource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL:    "http://localhost:8080",
					Header: map[string][]string{},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
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
		adapter := ProxyOnly{
			ApiDefinition:             apiDef,
			HttpClient:                httpClient,
			StreamingClient:           streamingClient,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		engineV2Config, err := adapter.EngineConfig()
		assert.NoError(t, err)

		expectedDataSource := plan.DataSourceConfiguration{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Query",
					FieldNames: []string{"hello"},
				},
			},
			ChildNodes: []plan.TypeField{},
			Factory: &graphqldatasource.Factory{
				BatchFactory:       graphqldatasource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL: "http://api-name",
					Header: http.Header{
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
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

	t.Run("should create v2 config for subgraph as proxy-only without error", func(t *testing.T) {
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
		adapter := ProxyOnly{
			ApiDefinition:             apiDef,
			HttpClient:                httpClient,
			StreamingClient:           streamingClient,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		engineV2Config, err := adapter.EngineConfig()
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
			Factory: &graphqldatasource.Factory{
				BatchFactory:       graphqldatasource.NewBatchFactory(),
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL:    "http://localhost:8080",
					Header: http.Header{},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
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
}

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
