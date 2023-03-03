package adapter

import (
	"testing"

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
