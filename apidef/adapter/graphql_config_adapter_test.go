package adapter

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	graphqlDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/graphql_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/httpclient"
	restDataSource "github.com/jensneuse/graphql-go-tools/pkg/engine/datasource/rest_datasource"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLConfigAdapter_EngineConfigV2(t *testing.T) {
	run := func(t *testing.T, inputJSON string, httpClient *http.Client) (*graphql.EngineV2Configuration, error) {
		var gqlConfig apidef.GraphQLConfig
		err := json.Unmarshal([]byte(inputJSON), &gqlConfig)
		require.NoError(t, err)

		adapter := NewGraphQLConfigAdapter(gqlConfig)
		adapter.SetHttpClient(httpClient)
		return adapter.EngineConfigV2()
	}

	runWithError := func(inputJSON string, expectedErr error) func(t *testing.T) {
		return func(t *testing.T) {
			_, err := run(t, inputJSON, nil)
			assert.Error(t, err)
			assert.Equal(t, expectedErr, err)
		}
	}

	runWithoutError := func(inputJSON string, httpClient *http.Client, expectedEngineV2ConfigBuilder func(t *testing.T) *graphql.EngineV2Configuration) func(t *testing.T) {
		return func(t *testing.T) {
			engineV2Conf, err := run(t, inputJSON, httpClient)
			expectedEngineV2Config := expectedEngineV2ConfigBuilder(t)

			assert.NoError(t, err)
			assert.Equal(t, expectedEngineV2Config, engineV2Conf)
		}
	}

	httpClient := &http.Client{}

	t.Run("should return error when provided config is not v2",
		runWithError(graphqlEngineV1ConfigJson, ErrUnsupportedGraphQLConfigVersion),
	)

	t.Run("should convert graphql v2 config to engine config v2",
		runWithoutError(graphqlEngineV2ConfigJson, httpClient,
			func(t *testing.T) *graphql.EngineV2Configuration {
				unquotedSchema, err := strconv.Unquote(v2Schema)
				require.NoError(t, err)

				schema, err := graphql.NewSchemaFromString(unquotedSchema)
				require.NoError(t, err)

				conf := graphql.NewEngineV2Configuration(schema)
				conf.SetFieldConfigurations(plan.FieldConfigurations{
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
				})

				conf.SetDataSources([]plan.DataSourceConfiguration{
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
				})

				return &conf
			},
		),
	)
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
