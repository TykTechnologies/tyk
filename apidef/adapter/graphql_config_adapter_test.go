package adapter

import (
	"encoding/json"
	"net/http"
	"testing"

	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	restDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLConfigAdapter_EngineConfigV2(t *testing.T) {
	t.Run("should create v2 config without err", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

		httpClient := &http.Client{}
		adapter := NewGraphQLConfigAdapter(gqlConfig)
		adapter.SetHttpClient(httpClient)

		_, err := adapter.EngineConfigV2()
		assert.NoError(t, err)
	})

	t.Run("should return an error for unsupported config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV1ConfigJson), &gqlConfig))

		adapter := NewGraphQLConfigAdapter(gqlConfig)
		_, err := adapter.EngineConfigV2()

		assert.Error(t, err)
		assert.Equal(t, ErrUnsupportedGraphQLConfigVersion, err)
	})
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

	adapter := NewGraphQLConfigAdapter(gqlConfig)
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
				Client: httpclient.NewNetHttpClient(httpClient),
			},
			Custom: restDataSource.ConfigJSON(restDataSource.Configuration{
				Fetch: restDataSource.FetchConfiguration{
					URL:    "https://rest.example.com",
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
				Client: httpclient.NewNetHttpClient(httpClient),
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
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
				Client: httpclient.NewNetHttpClient(httpClient),
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
				Client: httpclient.NewNetHttpClient(httpClient),
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
				Client: httpclient.NewNetHttpClient(httpClient),
			},
			Custom: graphqlDataSource.ConfigJson(graphqlDataSource.Configuration{
				Fetch: graphqlDataSource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: map[string][]string{
						"Auth": {"123"},
					},
				},
			}),
		},
	}

	var gqlConfig apidef.GraphQLConfig
	require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

	adapter := NewGraphQLConfigAdapter(gqlConfig)
	adapter.SetHttpClient(httpClient)
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

const v2Schema = `type Query { rest: String gql(id: ID!, name: String): String deepGQL: DeepGQL withChildren: WithChildren multiRoot1: MultiRoot1 multiRoot2: MultiRoot2 } type WithChildren { id: ID! name: String nested: Nested } type Nested { id: ID! name: String! } type MultiRoot1 { id: ID! } type MultiRoot2 { name: String! } type DeepGQL { query(code: String!): String }`

const graphqlEngineV2ConfigJson = `{
	"enabled": true,
	"execution_mode": "executionEngine",
	"version": "2",
	"schema": "` + v2Schema + `",
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
					"url": "https://rest.example.com",
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
				"internal": false,
				"root_fields": [
					{ "type": "Query", "fields": ["gql"] }
				],
				"config": {
					"url": "https://graphql.example.com",
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
			}
		]
	},
	"playground": {}
}`
