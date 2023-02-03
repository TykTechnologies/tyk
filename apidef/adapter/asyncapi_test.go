package adapter

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/require"
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

func TestGraphQLConfigAdapter_AsyncAPI(t *testing.T) {
	actualApiDefinition, err := ImportAsyncAPIDocument([]byte(streetlightsKafkaAsyncAPI))
	require.NoError(t, err)

	require.Equal(t, "Streetlights Kafka API - 1.0.0", actualApiDefinition.Name)
	require.True(t, actualApiDefinition.GraphQL.Enabled)
	require.True(t, actualApiDefinition.Active)
	require.Equal(t, apidef.GraphQLExecutionModeExecutionEngine, actualApiDefinition.GraphQL.ExecutionMode)
	require.Equal(t, expectedSchema, actualApiDefinition.GraphQL.Schema)
}
