package enginev3

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	graphqldatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/graphql_datasource"
	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/kafka_datasource"
	restdatasource "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/rest_datasource"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/plan"
	"github.com/TykTechnologies/tyk/apidef"
)

func TestUniversalDataGraph_EngineConfig(t *testing.T) {
	t.Run("should create v2 config for engine execution mode without error", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineV2ConfigJson), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		httpClient := &http.Client{}
		streamingClient := &http.Client{}
		adapter := UniversalDataGraph{
			ApiDefinition:             apiDef,
			HttpClient:                httpClient,
			StreamingClient:           streamingClient,
			subscriptionClientFactory: &MockSubscriptionClientFactory{},
		}

		_, err := adapter.EngineConfigV3()
		assert.NoError(t, err)
	})
}

func TestUniversalDataGraph_engineConfigV2FieldConfigs(t *testing.T) {
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

	httpClient := &http.Client{}
	streamingClient := &http.Client{}
	adapter := UniversalDataGraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: &MockSubscriptionClientFactory{},
	}

	var err error
	adapter.Schema, err = parseSchema(gqlConfig.Schema)
	require.NoError(t, err)

	actualFieldCfgs := adapter.engineConfigV2FieldConfigs()
	assert.ElementsMatch(t, expectedFieldCfgs, actualFieldCfgs)
}

func TestUniversalDataGraph_engineConfigV2DataSources(t *testing.T) {
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
					URL:    "tyk://rest-example",
					Method: "POST",
					Header: map[string][]string{
						"Authorization": {"123"},
						"X-Custom":      {"A, B"},
					},
					Body: "body",
					Query: []restdatasource.QueryConfiguration{
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
			Factory: &graphqldatasource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL:    "http://graphql-example",
					Method: "POST",
					Header: http.Header{
						"X-Tyk-Internal": []string{"true"},
					},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
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
			Factory: &graphqldatasource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: map[string][]string{
						"Auth": {"123"},
					},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
					URL:    "https://rest-with-query-params.example.com",
					Method: "POST",
					Query: []restdatasource.QueryConfiguration{
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
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
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
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
			Factory: &graphqldatasource.Factory{
				HTTPClient:         httpClient,
				StreamingClient:    streamingClient,
				SubscriptionClient: mockSubscriptionClient,
			},
			Custom: graphqldatasource.ConfigJson(graphqldatasource.Configuration{
				Fetch: graphqldatasource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: map[string][]string{
						"Auth": {"123"},
					},
				},
				Subscription: graphqldatasource.SubscriptionConfiguration{
					URL:    "https://graphql.example.com",
					UseSSE: false,
				},
			}),
		},
		{
			RootNodes: []plan.TypeField{
				{
					TypeName:   "Nested",
					FieldNames: []string{"nestedGql"},
				},
			},
			ChildNodes: nil,
			Factory: &restdatasource.Factory{
				Client: httpClient,
			},
			Custom: restdatasource.ConfigJSON(restdatasource.Configuration{
				Fetch: restdatasource.FetchConfiguration{
					URL:    "https://graphql.example.com",
					Method: "POST",
					Header: http.Header{
						"Auth": []string{"123"},
					},
					Query: nil,
					Body:  `{"variables":"","query":"{ fromNested }"}`,
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
			Factory: &kafkadatasource.Factory{},
			Custom: kafkadatasource.ConfigJSON(kafkadatasource.Configuration{
				Subscription: kafkadatasource.SubscriptionConfiguration{
					BrokerAddresses:      []string{"localhost:9092"},
					Topics:               []string{"test.topic"},
					GroupID:              "test.consumer.group",
					ClientID:             "test.client.id",
					KafkaVersion:         "V2_8_0_0",
					StartConsumingLatest: true,
					BalanceStrategy:      kafkadatasource.BalanceStrategySticky,
					IsolationLevel:       kafkadatasource.IsolationLevelReadCommitted,
					SASL: kafkadatasource.SASL{
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
			Factory: &kafkadatasource.Factory{},
			Custom: kafkadatasource.ConfigJSON(kafkadatasource.Configuration{
				Subscription: kafkadatasource.SubscriptionConfiguration{
					BrokerAddresses:      []string{"localhost:9092"},
					Topics:               []string{"test.topic.{{.arguments.name}}"},
					GroupID:              "test.consumer.group",
					ClientID:             "test.client.id",
					KafkaVersion:         "V2_8_0_0",
					StartConsumingLatest: true,
					BalanceStrategy:      kafkadatasource.BalanceStrategySticky,
					IsolationLevel:       kafkadatasource.IsolationLevelReadCommitted,
					SASL: kafkadatasource.SASL{
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

	adapter := UniversalDataGraph{
		ApiDefinition:             apiDef,
		HttpClient:                httpClient,
		StreamingClient:           streamingClient,
		subscriptionClientFactory: &MockSubscriptionClientFactory{},
	}

	var err error
	adapter.Schema, err = parseSchema(gqlConfig.Schema)
	require.NoError(t, err)

	actualDataSources, err := adapter.engineConfigV2DataSources()
	assert.NoError(t, err)
	assert.Equal(t, expectedDataSources, actualDataSources)
	//assert.ElementsMatch(t, expectedDataSources, actualDataSources)
}

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
  nestedGql: String!
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
				"kind": "GraphQL",
				"internal": false,
				"root_fields": [
					{ "type": "Nested", "fields": ["nestedGql"] }
				],
				"config": {
					"url": "https://graphql.example.com",
					"method": "POST",
					"headers": {
						"Auth": "123"
					},
					"has_operation": true,
					"operation": "{ fromNested }",
					"variables": ""
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
