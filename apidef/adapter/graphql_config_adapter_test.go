package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGraphQLConfigAdapter_EngineConfigV2(t *testing.T) {
	t.Run("should return no error when having a proxy-only config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlMinimalProxyOnlyConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.NoError(t, err)
	})

	t.Run("should return no error when having a subgraph config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlMinimalSubgraphConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.NoError(t, err)
	})

	t.Run("should return no error when having a supergraph config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlMinimalSupergraphConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.NoError(t, err)
	})

	t.Run("should return no error when having a udg config", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlMinimalUniversalDataGraphConfig), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.NoError(t, err)
	})

	t.Run("should return an error for unsupported execution mode", func(t *testing.T) {
		var gqlConfig apidef.GraphQLConfig
		require.NoError(t, json.Unmarshal([]byte(graphqlEngineUnknownExecutionMode), &gqlConfig))

		apiDef := &apidef.APIDefinition{
			GraphQL: gqlConfig,
		}

		adapter := NewGraphQLConfigAdapter(apiDef)
		_, err := adapter.EngineConfigV2()

		assert.Error(t, err)
		assert.Equal(t, ErrUnsupportedGraphQLExecutionMode, err)
	})

	t.Run("should return an error for legacy config", func(t *testing.T) {
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

const graphqlEngineV1ConfigJson = `{
	"enabled": true,
	"execution_mode": "executionEngine",
	"schema": "type Query { rest: String, gql: String }",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"playground": {}
}`

const graphqlEngineUnknownExecutionMode = `{
	"enabled": true,
	"execution_mode": "unknown",
	"version": "2",
	"schema": "type Query { rest: String, gql: String }",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"playground": {}
}`

var graphqlMinimalProxyOnlyConfig = `{
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

var graphqlMinimalSubgraphConfig = `{
	"enabled": true,
	"execution_mode": "subgraph",
	"version": "2",
	"schema": "type Query { hello: String }",
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
		"sdl": "extend type Query { hello: String }",
		"subscription_type": "graphql-transport-ws"
	},
	"playground": {}
}`

var graphqlMinimalSupergraphConfig = `{
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
				"sdl": "extend type Query {me: User}",
				"headers": {},
				"subscription_type": "sse"
			}
		],
		"global_headers": {},
		"merged_sdl": "type Query { me: User }"
	},
	"playground": {}
}`

var graphqlMinimalUniversalDataGraphConfig = `{
	"enabled": true,
	"execution_mode": "executionEngine",
	"version": "2",
	"schema": "type Query { hello: String }",
	"last_schema_update": "2020-11-11T11:11:11.000+01:00",
	"engine": {
		"field_configs": [
			{
				"type_name": "Query",
				"field_name": "hello",
				"disable_default_mapping": false
			}
		],
		"data_sources": [
			{
				"kind": "REST",
				"name": "",
				"internal": true,
				"root_fields": [
					{ "type": "Query", "fields": ["hello"] }
				],
				"config": {
					"url": "tyk://rest-example",
					"method": "POST",
					"headers": {},
					"query": [],
					"body": ""
				}
			}
		]
	},
	"playground": {}
}`
