package adapter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	restDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"

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
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

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
				BatchFactory: graphqlDataSource.NewBatchFactory(),
				HTTPClient:   httpClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL: "http://localhost:8080",
					Header: http.Header{
						"Authorization": []string{"123abc"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL: "http://localhost:8080",
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
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

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
				BatchFactory: graphqlDataSource.NewBatchFactory(),
				HTTPClient:   httpClient,
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
					URL: "http://api-name",
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
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

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
				HTTPClient: httpClient,
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
					URL: "http://accounts.service",
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
		adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))

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
				BatchFactory: graphqlDataSource.NewBatchFactory(),
				HTTPClient:   httpClient,
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL: "http://localhost:8080",
					Header: http.Header{
						"Authorization": []string{"123abc"},
					},
				},
				Subscription: graphqlDataSource.SubscriptionConfiguration{
					URL: "http://localhost:8080",
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
				URL: "http://accounts.service",
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
				HTTPClient: httpClient,
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
					URL: "http://graphql-example",
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
					FieldNames: []string{"id", "name"},
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
					FieldNames: []string{"id", "name"},
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
					FieldNames: []string{"id"},
				},
				{
					TypeName:   "MultiRoot2",
					FieldNames: []string{"name"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient: httpClient,
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
					URL: "https://graphql.example.com",
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
					FieldNames: []string{"id", "name"},
				},
				{
					TypeName:   "IDType",
					FieldNames: []string{"id"},
				},
			},
			Factory: &graphqlDataSource.Factory{
				HTTPClient: httpClient,
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
					URL: "https://graphql.example.com",
				},
			}),
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

	apiDef := &apidef.APIDefinition{
		GraphQL: gqlConfig,
	}

	adapter := NewGraphQLConfigAdapter(apiDef, WithHttpClient(httpClient))
	require.NoError(t, adapter.parseSchema())

	actualDataSources, err := adapter.engineConfigV2DataSources()
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedDataSources, actualDataSources)
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
					"method": "POST"
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
				}
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
		}
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
		"sdl": ` + strconv.Quote(federationAccountsServiceSDL) + `
	},
	"playground": {}
}`

const graphqlSubgraphSchema = `scalar _Any scalar _FieldSet union _Entity = User type _Service { sdl: String } type Query { me: User _entities(representations: [_Any!]!): [_Entity]! _service: _Service! } type User { id: ID! username: String! }`
