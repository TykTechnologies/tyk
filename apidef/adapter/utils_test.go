package adapter

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestIsSupergraphAPIDefinition(t *testing.T) {
	type testInput struct {
		graphQLEnabled bool
		executionModes []apidef.GraphQLExecutionMode
		expectedResult bool
	}
	run := func(input testInput) func(t *testing.T) {
		return func(t *testing.T) {
			for _, executionMode := range input.executionModes {
				apiDef := &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						Enabled:       input.graphQLEnabled,
						ExecutionMode: executionMode,
					},
				}
				assert.Equal(t, input.expectedResult, isSupergraphAPIDefinition(apiDef))
			}
		}
	}

	t.Run("false if graphql is disabled", run(
		testInput{
			graphQLEnabled: false,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeSupergraph,
				apidef.GraphQLExecutionModeProxyOnly,
				apidef.GraphQLExecutionModeExecutionEngine,
				apidef.GraphQLExecutionModeSubgraph,
			},
			expectedResult: false,
		},
	))

	t.Run("false if execution mode is not supergraph", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeProxyOnly,
				apidef.GraphQLExecutionModeExecutionEngine,
				apidef.GraphQLExecutionModeSubgraph,
			},
			expectedResult: false,
		},
	))

	t.Run("true if graphql is enabled and execution mode is supergraph", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeSupergraph,
			},
			expectedResult: true,
		},
	))
}

func TestIsProxyOnlyAPIDefinition(t *testing.T) {
	type testInput struct {
		graphQLEnabled bool
		executionModes []apidef.GraphQLExecutionMode
		expectedResult bool
	}
	run := func(input testInput) func(t *testing.T) {
		return func(t *testing.T) {
			for _, executionMode := range input.executionModes {
				apiDef := &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						Enabled:       input.graphQLEnabled,
						ExecutionMode: executionMode,
					},
				}
				assert.Equal(t, input.expectedResult, isProxyOnlyAPIDefinition(apiDef))
			}
		}
	}

	t.Run("false if graphql is disabled", run(
		testInput{
			graphQLEnabled: false,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeProxyOnly,
				apidef.GraphQLExecutionModeExecutionEngine,
				apidef.GraphQLExecutionModeSubgraph,
				apidef.GraphQLExecutionModeSupergraph,
			},
			expectedResult: false,
		},
	))

	t.Run("false if execution mode is not proxyOnly or subgraph", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeExecutionEngine,
				apidef.GraphQLExecutionModeSupergraph,
			},
			expectedResult: false,
		},
	))

	t.Run("true if graphql is enabled and execution mode is proxyOnly", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeProxyOnly,
				apidef.GraphQLExecutionModeSubgraph,
			},
			expectedResult: true,
		},
	))
}

func TestGraphqlSubscriptionType(t *testing.T) {
	run := func(subscriptionType apidef.SubscriptionType, expectedGraphQLSubscriptionType graphql.SubscriptionType) func(t *testing.T) {
		return func(t *testing.T) {
			actualSubscriptionType := graphqlSubscriptionType(subscriptionType)
			assert.Equal(t, expectedGraphQLSubscriptionType, actualSubscriptionType)
		}
	}

	t.Run("should return 'Unknown' for undefined subscription type",
		run(apidef.GQLSubscriptionUndefined, graphql.SubscriptionTypeUnknown),
	)

	t.Run("should return 'SSE' for sse subscription type as websocket protocol is irrelevant in that case",
		run(apidef.GQLSubscriptionSSE, graphql.SubscriptionTypeSSE),
	)

	t.Run("should return 'GraphQLWS' for graphql-ws subscription type",
		run(apidef.GQLSubscriptionWS, graphql.SubscriptionTypeGraphQLWS),
	)

	t.Run("should return 'GraphQLTransportWS' for graphql-transport-ws subscription type",
		run(apidef.GQLSubscriptionTransportWS, graphql.SubscriptionTypeGraphQLTransportWS),
	)
}

func TestConvertApiDefinitionHeadersToHttpHeaders(t *testing.T) {
	t.Run("should return nil for empty input", func(t *testing.T) {
		assert.Nil(t, convertApiDefinitionHeadersToHttpHeaders(nil))
	})

	t.Run("should successfully convert API Definition header to Http Headers", func(t *testing.T) {
		apiDefinitionHeaders := map[string]string{
			"Authorization": "token",
			"X-Tyk-Key":     "value",
		}

		expectedHttpHeaders := http.Header{
			"Authorization": {"token"},
			"X-Tyk-Key":     {"value"},
		}

		actualHttpHeaders := convertApiDefinitionHeadersToHttpHeaders(apiDefinitionHeaders)
		assert.Equal(t, expectedHttpHeaders, actualHttpHeaders)
	})
}

func TestRemoveDuplicateApiDefinitionHeaders(t *testing.T) {
	apiDefinitionHeadersFirstArgument := map[string]string{
		"duplicate-header": "value",
	}
	apiDefinitionHeadersSecondArgument := map[string]string{
		"Duplicate-Header":     "value",
		"Non-Duplicate-Header": "another_value",
	}

	expectedDeduplicatedHeaders := map[string]string{
		"Duplicate-Header":     "value",
		"Non-Duplicate-Header": "another_value",
	}

	actualDeduplicatedHeaders := removeDuplicateApiDefinitionHeaders(apiDefinitionHeadersFirstArgument, apiDefinitionHeadersSecondArgument)
	assert.Equal(t, expectedDeduplicatedHeaders, actualDeduplicatedHeaders)
}
