package adapter

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	gqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

// Verifies: SYS-REQ-104, SW-REQ-069
// SW-REQ-069:nominal:nominal
// SW-REQ-069:error_handling:nominal
// SW-REQ-069:error_handling:negative
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

// Verifies: SYS-REQ-104, SW-REQ-069
// SW-REQ-069:nominal:nominal
// SW-REQ-069:boundary:nominal
// SW-REQ-069:error_handling:nominal
// SW-REQ-069:error_handling:negative
// SW-REQ-069:determinism:nominal
func TestGraphQLConfigAdapterPreservesLocalSelectionAndOptions(t *testing.T) {
	t.Run("constructor applies supplied options and preserves API definition", func(t *testing.T) {
		apiDef := &apidef.APIDefinition{Name: "orders"}
		schema := &graphql.Schema{}
		schemaV2 := &gqlv2.Schema{}
		httpClient := &http.Client{Timeout: time.Second}
		streamingClient := &http.Client{Timeout: 2 * time.Second}

		adapter := NewGraphQLConfigAdapter(
			apiDef,
			WithSchema(schema),
			WithV2Schema(schemaV2),
			WithHttpClient(httpClient),
			WithStreamingClient(streamingClient),
		)

		assert.Same(t, apiDef, adapter.apiDefinition)
		assert.Same(t, schema, adapter.schema)
		assert.Same(t, schemaV2, adapter.schemaV2)
		assert.Same(t, httpClient, adapter.getHttpClient())
		assert.Same(t, streamingClient, adapter.getStreamingClient())
	})

	t.Run("nil clients are initialized to deterministic nonnil defaults", func(t *testing.T) {
		adapter := NewGraphQLConfigAdapter(&apidef.APIDefinition{})

		assert.NotNil(t, adapter.getHttpClient())
		streamingClient := adapter.getStreamingClient()
		require.NotNil(t, streamingClient)
		assert.Equal(t, time.Duration(0), streamingClient.Timeout)
		assert.Same(t, streamingClient, adapter.getStreamingClient())
	})

	t.Run("v3 rejects unsupported version, supergraph mode, and unknown execution mode explicitly", func(t *testing.T) {
		legacy := NewGraphQLConfigAdapter(&apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				Version:       apidef.GraphQLConfigVersion2,
				ExecutionMode: apidef.GraphQLExecutionModeProxyOnly,
			},
		})
		_, err := legacy.EngineConfigV3()
		assert.ErrorIs(t, err, ErrUnsupportedGraphQLConfigVersion)

		supergraph := NewGraphQLConfigAdapter(&apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				Version:       apidef.GraphQLConfigVersion3Preview,
				ExecutionMode: apidef.GraphQLExecutionModeSupergraph,
			},
		})
		_, err = supergraph.EngineConfigV3()
		assert.ErrorIs(t, err, ErrUnsupportedGraphQLConfigVersion)

		unknown := NewGraphQLConfigAdapter(&apidef.APIDefinition{
			GraphQL: apidef.GraphQLConfig{
				Enabled:       true,
				Version:       apidef.GraphQLConfigVersion3Preview,
				ExecutionMode: apidef.GraphQLExecutionMode("unknown"),
			},
		})
		_, err = unknown.EngineConfigV3()
		assert.ErrorIs(t, err, ErrUnsupportedGraphQLExecutionMode)
	})

	t.Run("v3 proxy-only and universal data graph configs delegate without local selection error", func(t *testing.T) {
		for name, config := range map[string]string{
			"proxy only":           graphqlMinimalProxyOnlyConfig,
			"universal data graph": graphqlMinimalUniversalDataGraphConfig,
		} {
			t.Run(name, func(t *testing.T) {
				var gqlConfig apidef.GraphQLConfig
				v3Config := strings.Replace(config, `"version": "2"`, `"version": "3-preview"`, 1)
				require.NoError(t, json.Unmarshal([]byte(v3Config), &gqlConfig))

				adapter := NewGraphQLConfigAdapter(&apidef.APIDefinition{GraphQL: gqlConfig})
				_, err := adapter.EngineConfigV3()

				assert.False(t, errors.Is(err, ErrUnsupportedGraphQLConfigVersion))
				assert.False(t, errors.Is(err, ErrUnsupportedGraphQLExecutionMode))
			})
		}
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
