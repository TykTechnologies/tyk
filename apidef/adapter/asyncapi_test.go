package adapter

import (
	"bytes"
	"encoding/json"
	"testing"

	kafkadatasource "github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/kafka_datasource"
	"github.com/TykTechnologies/graphql-translator/asyncapi"
	"github.com/buger/jsonparser"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

const streetlightsKafkaAsyncAPI = `asyncapi: '2.4.0'
info:
  title: Streetlights Kafka API
  version: '1.0.0'
  description: |
    The Smartylighting Streetlights API allows you to remotely manage the city lights.

    ### Check out its awesome features:

    * Turn a specific streetlight on/off 🌃
    * Dim a specific streetlight 😎
    * Receive real-time information about environmental lighting conditions 📈
  license:
    name: Apache 2.0
    url: https://www.apache.org/licenses/LICENSE-2.0

servers:
  test:
    url: test.mykafkacluster.org:8092
    protocol: kafka-secure
    description: Test broker
    bindings:
      kafka:
        clientId: my-app-id
        groupId: my-group-id
    security:
      - saslScram: []

defaultContentType: application/json

channels:
  smartylighting.streetlights.1.0.event.{streetlightId}.lighting.measured:
    description: The topic on which measured values may be produced and consumed.
    parameters:
      streetlightId:
        $ref: '#/components/parameters/streetlightId'
    publish:
      summary: Inform about environmental lighting conditions of a particular streetlight.
      operationId: receiveLightMeasurement
      traits:
        - $ref: '#/components/operationTraits/kafka'
      message:
        $ref: '#/components/messages/lightMeasured'

  smartylighting.streetlights.1.0.action.{streetlightId}.turn.on:
    parameters:
      streetlightId:
        $ref: '#/components/parameters/streetlightId'
    subscribe:
      operationId: turnOn
      traits:
        - $ref: '#/components/operationTraits/kafka'
      message:
        $ref: '#/components/messages/turnOnOff'

  smartylighting.streetlights.1.0.action.{streetlightId}.turn.off:
    parameters:
      streetlightId:
        $ref: '#/components/parameters/streetlightId'
    subscribe:
      operationId: turnOff
      traits:
        - $ref: '#/components/operationTraits/kafka'
      message:
        $ref: '#/components/messages/turnOnOff'

  smartylighting.streetlights.1.0.action.{streetlightId}.dim:
    parameters:
      streetlightId:
        $ref: '#/components/parameters/streetlightId'
    subscribe:
      operationId: dimLight
      traits:
        - $ref: '#/components/operationTraits/kafka'
      message:
        $ref: '#/components/messages/dimLight'

components:
  messages:
    lightMeasured:
      name: lightMeasured
      title: Light measured
      summary: Inform about environmental lighting conditions of a particular streetlight.
      contentType: application/json
      traits:
        - $ref: '#/components/messageTraits/commonHeaders'
      payload:
        $ref: "#/components/schemas/lightMeasuredPayload"
    turnOnOff:
      name: turnOnOff
      title: Turn on/off
      summary: Command a particular streetlight to turn the lights on or off.
      traits:
        - $ref: '#/components/messageTraits/commonHeaders'
      payload:
        $ref: "#/components/schemas/turnOnOffPayload"
    dimLight:
      name: dimLight
      title: Dim light
      summary: Command a particular streetlight to dim the lights.
      traits:
        - $ref: '#/components/messageTraits/commonHeaders'
      payload:
        $ref: "#/components/schemas/dimLightPayload"

  schemas:
    lightMeasuredPayload:
      type: object
      properties:
        lumens:
          type: integer
          minimum: 0
          description: Light intensity measured in lumens.
        sentAt:
          $ref: "#/components/schemas/sentAt"
    turnOnOffPayload:
      type: object
      properties:
        command:
          type: string
          enum:
            - on
            - off
          description: Whether to turn on or off the light.
        sentAt:
          $ref: "#/components/schemas/sentAt"
    dimLightPayload:
      type: object
      properties:
        percentage:
          type: integer
          description: Percentage to which the light should be dimmed to.
          minimum: 0
          maximum: 100
        sentAt:
          $ref: "#/components/schemas/sentAt"
    sentAt:
      type: string
      format: date-time
      description: Date and time when the message was sent.

  securitySchemes:
    saslScram:
      type: scramSha256
      description: Provide your username and password for SASL/SCRAM authentication

  parameters:
    streetlightId:
      description: The ID of the streetlight.
      schema:
        type: string

  messageTraits:
    commonHeaders:
      headers:
        type: object
        properties:
          my-app-header:
            type: integer
            minimum: 0
            maximum: 100

  operationTraits:
    kafka:
      bindings:
        kafka:
          clientId:
            type: string
            enum: ['my-app-id']`

const expectedSchema = "schema {\n    query: Query\n    subscription: Subscription\n}\n\ntype Query {\n    _: Boolean\n}\n\ntype Subscription {\n    dimLight(streetlightId: String): DimLight\n    turnOff(streetlightId: String): TurnOnOff\n    turnOn(streetlightId: String): TurnOnOff\n}\n\nenum Command {\n    ON\n    OFF\n}\n\n\"\"\"\nDim light\nCommand a particular streetlight to dim the lights.\n\"\"\"\ntype DimLight {\n    \"Percentage to which the light should be dimmed to.\"\n    percentage: Int\n    \"Date and time when the message was sent.\"\n    sentAt: String\n}\n\n\"\"\"\nTurn on/off\nCommand a particular streetlight to turn the lights on or off.\n\"\"\"\ntype TurnOnOff {\n    \"Whether to turn on or off the light.\"\n    command: Command\n    \"Date and time when the message was sent.\"\n    sentAt: String\n}"

const expectedGraphqlConfig = `{
    "enabled": true,
    "execution_mode": "executionEngine",
    "version": "2",
    "schema": "schema {\n    query: Query\n    subscription: Subscription\n}\n\ntype Query {\n    _: Boolean\n}\n\ntype Subscription {\n    dimLight(streetlightId: String): DimLight\n    turnOff(streetlightId: String): TurnOnOff\n    turnOn(streetlightId: String): TurnOnOff\n}\n\nenum Command {\n    ON\n    OFF\n}\n\n\"\"\"\nDim light\nCommand a particular streetlight to dim the lights.\n\"\"\"\ntype DimLight {\n    \"Percentage to which the light should be dimmed to.\"\n    percentage: Int\n    \"Date and time when the message was sent.\"\n    sentAt: String\n}\n\n\"\"\"\nTurn on/off\nCommand a particular streetlight to turn the lights on or off.\n\"\"\"\ntype TurnOnOff {\n    \"Whether to turn on or off the light.\"\n    command: Command\n    \"Date and time when the message was sent.\"\n    sentAt: String\n}",
    "type_field_configurations": null,
    "playground": {
        "enabled": false,
        "path": ""
    },
    "engine": {
        "field_configs": [
            {
                "type_name": "Subscription",
                "field_name": "dimLight",
                "disable_default_mapping": false,
                "path": [
                    "dimLight"
                ]
            },
            {
                "type_name": "Subscription",
                "field_name": "turnOff",
                "disable_default_mapping": false,
                "path": [
                    "turnOff"
                ]
            },
            {
                "type_name": "Subscription",
                "field_name": "turnOn",
                "disable_default_mapping": false,
                "path": [
                    "turnOn"
                ]
            }
        ],
        "data_sources": [
            {
                "kind": "Kafka",
                "name": "consumer-group:dimLight",
                "internal": false,
                "root_fields": [
                    {
                        "type": "Subscription",
                        "fields": [
                            "dimLight"
                        ]
                    }
                ],
                "config": {
                    "broker_addresses": [
                        "test.mykafkacluster.org:8092"
                    ],
                    "topics": [
                        "smartylighting.streetlights.1.0.action.{{.arguments.streetlightId}}.dim"
                    ],
                    "group_id": "my-group-id",
                    "client_id": "my-app-id",
                    "kafka_version": "V1_0_0_0",
                    "start_consuming_latest": false,
                    "balance_strategy": "BalanceStrategyRange",
                    "isolation_level": "ReadUncommitted",
                    "sasl": {
                        "enable": false,
                        "user": "",
                        "password": ""
                    }
                }
            },
            {
                "kind": "Kafka",
                "name": "consumer-group:turnOff",
                "internal": false,
                "root_fields": [
                    {
                        "type": "Subscription",
                        "fields": [
                            "turnOff"
                        ]
                    }
                ],
                "config": {
                    "broker_addresses": [
                        "test.mykafkacluster.org:8092"
                    ],
                    "topics": [
                        "smartylighting.streetlights.1.0.action.{{.arguments.streetlightId}}.turn.off"
                    ],
                    "group_id": "my-group-id",
                    "client_id": "my-app-id",
                    "kafka_version": "V1_0_0_0",
                    "start_consuming_latest": false,
                    "balance_strategy": "BalanceStrategyRange",
                    "isolation_level": "ReadUncommitted",
                    "sasl": {
                        "enable": false,
                        "user": "",
                        "password": ""
                    }
                }
            },
            {
                "kind": "Kafka",
                "name": "consumer-group:turnOn",
                "internal": false,
                "root_fields": [
                    {
                        "type": "Subscription",
                        "fields": [
                            "turnOn"
                        ]
                    }
                ],
                "config": {
                    "broker_addresses": [
                        "test.mykafkacluster.org:8092"
                    ],
                    "topics": [
                        "smartylighting.streetlights.1.0.action.{{.arguments.streetlightId}}.turn.on"
                    ],
                    "group_id": "my-group-id",
                    "client_id": "my-app-id",
                    "kafka_version": "V1_0_0_0",
                    "start_consuming_latest": false,
                    "balance_strategy": "BalanceStrategyRange",
                    "isolation_level": "ReadUncommitted",
                    "sasl": {
                        "enable": false,
                        "user": "",
                        "password": ""
                    }
                }
            }
        ],
        "global_headers": null
    },
    "proxy": {
        "features": {
            "use_immutable_headers": false
        },
        "auth_headers": {},
        "sse_use_post": false,
        "request_headers": null,
        "use_response_extensions": {
            "on_error_forwarding": false
        },
        "request_headers_rewrite": null
    },
    "subgraph": {
        "sdl": ""
    },
    "supergraph": {
        "subgraphs": null,
        "merged_sdl": "",
        "global_headers": null,
        "disable_query_batching": false
    },
    "introspection": {
        "disabled": false
    }
}`

const asyncAPIWithSelectedKafkaServer = `asyncapi: '2.4.0'
info:
  title: Selected Kafka API
  version: '1.0.0'
servers:
  primary:
    url: primary.kafka.local:9092
    protocol: kafka
  secondary:
    url: secondary.kafka.local:9093
    protocol: kafka-secure
    bindings:
      kafka:
        clientId: client-{tenantId}
        groupId: group-{tenantId}
channels:
  tenant.{tenantId}.event.{eventId}:
    servers:
      - secondary
    subscribe:
      operationId: tenantEvent
      message:
        payload:
          type: object
          properties:
            id:
              type: string`

const unsupportedKafkaProtocolAsyncAPI = `asyncapi: '2.4.0'
info:
  title: Unsupported Kafka API
  version: '1.0.0'
servers:
  unsupported:
    url: broker.kafka.local:9092
    protocol: http
channels:
  events:
    subscribe:
      operationId: unsupportedEvent
      message:
        payload:
          type: object
          properties:
            id:
              type: string`

const missingKafkaURLAsyncAPI = `asyncapi: '2.4.0'
info:
  title: Missing Kafka URL API
  version: '1.0.0'
servers:
  missing:
    protocol: kafka
channels:
  events:
    subscribe:
      operationId: missingURLEvent
      message:
        payload:
          type: object
          properties:
            id:
              type: string`

// Verifies: SYS-REQ-104, SW-REQ-070
// SW-REQ-070:nominal:nominal
// SW-REQ-070:boundary:nominal
// SW-REQ-070:error_handling:nominal
// SW-REQ-070:error_handling:negative
// SW-REQ-070:determinism:nominal
func TestGraphQLConfigAdapter_AsyncAPI(t *testing.T) {
	importer := NewAsyncAPIAdapter("my-org-id", []byte(streetlightsKafkaAsyncAPI))

	actualApiDefinition, err := importer.Import()
	require.NoError(t, err)

	require.Equal(t, "Streetlights Kafka API", actualApiDefinition.Name)
	require.True(t, actualApiDefinition.GraphQL.Enabled)
	require.True(t, actualApiDefinition.Active)
	require.Equal(t, apidef.GraphQLExecutionModeExecutionEngine, actualApiDefinition.GraphQL.ExecutionMode)
	require.Equal(t, expectedSchema, actualApiDefinition.GraphQL.Schema)

	data, err := json.Marshal(actualApiDefinition)
	require.NoError(t, err)

	actualGraphqlConfig, _, _, err := jsonparser.Get(data, "graphql")
	require.NoError(t, err)

	dst := bytes.NewBuffer(nil)
	err = json.Indent(dst, actualGraphqlConfig, "", "    ")
	require.NoError(t, err)
	require.Equal(t, expectedGraphqlConfig, dst.String())
}

// Verifies: SYS-REQ-104, SW-REQ-070
// SW-REQ-070:nominal:nominal
// SW-REQ-070:boundary:nominal
// SW-REQ-070:determinism:nominal
func TestAsyncAPIAdapterKafkaServerSelectionAndArgumentTemplates(t *testing.T) {
	require.Equal(t, "tenant.{{.arguments.tenantId}}.event.{{.arguments.eventId}}", processArgumentSection("tenant.{tenantId}.event.{eventId}"))
	require.Equal(t, "plain-topic", processArgumentSection("plain-topic"))

	importer := NewAsyncAPIAdapter("my-org-id", []byte(asyncAPIWithSelectedKafkaServer))

	actualApiDefinition, err := importer.Import()
	require.NoError(t, err)

	require.Equal(t, "Selected Kafka API", actualApiDefinition.Name)
	require.Len(t, actualApiDefinition.GraphQL.Engine.FieldConfigs, 1)
	require.Equal(t, apidef.GraphQLFieldConfig{
		TypeName:  "Subscription",
		FieldName: "tenantEvent",
		Path:      []string{"tenantEvent"},
	}, actualApiDefinition.GraphQL.Engine.FieldConfigs[0])
	require.Len(t, actualApiDefinition.GraphQL.Engine.DataSources, 1)

	dataSource := actualApiDefinition.GraphQL.Engine.DataSources[0]
	require.Equal(t, apidef.GraphQLEngineDataSourceKind(apidef.GraphQLEngineDataSourceKindKafka), dataSource.Kind)
	require.Equal(t, "consumer-group:tenantEvent", dataSource.Name)
	require.Equal(t, []apidef.GraphQLTypeFields{
		{Type: "Subscription", Fields: []string{"tenantEvent"}},
	}, dataSource.RootFields)

	var config map[string]any
	require.NoError(t, json.Unmarshal(dataSource.Config, &config))
	require.Equal(t, []any{"secondary.kafka.local:9093"}, config["broker_addresses"])
	require.Equal(t, []any{"tenant.{{.arguments.tenantId}}.event.{{.arguments.eventId}}"}, config["topics"])
	require.Equal(t, "group-{{.arguments.tenantId}}", config["group_id"])
	require.Equal(t, "client-{{.arguments.tenantId}}", config["client_id"])
	require.Contains(t, actualApiDefinition.GraphQL.Schema, "tenantEvent")

	repeatedImporter := NewAsyncAPIAdapter("my-org-id", []byte(asyncAPIWithSelectedKafkaServer))
	repeatedApiDefinition, err := repeatedImporter.Import()
	require.NoError(t, err)
	require.Equal(t, actualApiDefinition.GraphQL.Engine.FieldConfigs, repeatedApiDefinition.GraphQL.Engine.FieldConfigs)
	require.Equal(t, actualApiDefinition.GraphQL.Engine.DataSources, repeatedApiDefinition.GraphQL.Engine.DataSources)
}

// Verifies: SYS-REQ-104, SW-REQ-070
// SW-REQ-070:error_handling:negative
// MCDC SYS-REQ-104: api_definition_support_requested=T, api_definition_support_shape_preserved=F => FALSE
func TestAsyncAPIAdapterRejectsMalformedAndUnsupportedKafkaInput(t *testing.T) {
	_, err := NewAsyncAPIAdapter("my-org-id", []byte("asyncapi: [")).Import()
	require.Error(t, err)

	_, err = NewAsyncAPIAdapter("my-org-id", []byte(unsupportedKafkaProtocolAsyncAPI)).Import()
	require.ErrorContains(t, err, "invalid server protocol: http")

	_, err = NewAsyncAPIAdapter("my-org-id", []byte(missingKafkaURLAsyncAPI)).Import()
	require.ErrorContains(t, err, "url is required")

	_, err = prepareKafkaDataSourceConfig(&asyncapi.AsyncAPI{
		Servers: map[string]*asyncapi.Server{
			"missing": {Protocol: "kafka"},
		},
	})
	require.ErrorContains(t, err, "server.URL cannot be empty")

	_, err = encodeKafkaDataSourceConfig(kafklessSubscriptionOptions(), "topic")
	require.Error(t, err)
}

func kafklessSubscriptionOptions() kafkadatasource.GraphQLSubscriptionOptions {
	return kafkadatasource.GraphQLSubscriptionOptions{}
}
