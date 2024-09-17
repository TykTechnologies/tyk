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
			t.Helper()
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
			t.Helper()
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

func TestIsUniversalDataGraphAPIDefinition(t *testing.T) {
	type testInput struct {
		graphQLEnabled bool
		executionModes []apidef.GraphQLExecutionMode
		expectedResult bool
	}
	run := func(input testInput) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			for _, executionMode := range input.executionModes {
				apiDef := &apidef.APIDefinition{
					GraphQL: apidef.GraphQLConfig{
						Enabled:       input.graphQLEnabled,
						ExecutionMode: executionMode,
					},
				}
				assert.Equal(t, input.expectedResult, isUniversalDataGraphAPIDefinition(apiDef))
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

	t.Run("false if execution mode is not executionEngine", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeProxyOnly,
				apidef.GraphQLExecutionModeSupergraph,
				apidef.GraphQLExecutionModeSubgraph,
			},
			expectedResult: false,
		},
	))

	t.Run("true if graphql is enabled and execution mode is executionEngine", run(
		testInput{
			graphQLEnabled: true,
			executionModes: []apidef.GraphQLExecutionMode{
				apidef.GraphQLExecutionModeExecutionEngine,
			},
			expectedResult: true,
		},
	))
}

func TestGraphqlEngineAdapterTypeFromApiDefinition(t *testing.T) {
	type testInput struct {
		executionMode  apidef.GraphQLExecutionMode
		expectedResult GraphQLEngineAdapterType
	}

	run := func(input testInput) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			apiDef := &apidef.APIDefinition{
				GraphQL: apidef.GraphQLConfig{
					Enabled:       true,
					ExecutionMode: input.executionMode,
				},
			}
			assert.Equal(t, input.expectedResult, graphqlEngineAdapterTypeFromApiDefinition(apiDef))
		}
	}

	t.Run("should return adapter type proxy only for execution mode proxy only", run(
		testInput{
			executionMode:  apidef.GraphQLExecutionModeProxyOnly,
			expectedResult: GraphQLEngineAdapterTypeProxyOnly,
		},
	))

	t.Run("should return adapter type proxy only for execution mode subgraph", run(
		testInput{
			executionMode:  apidef.GraphQLExecutionModeSubgraph,
			expectedResult: GraphQLEngineAdapterTypeProxyOnly,
		},
	))

	t.Run("should return adapter type supergraph for execution mode supergraph", run(
		testInput{
			executionMode:  apidef.GraphQLExecutionModeSupergraph,
			expectedResult: GraphQLEngineAdapterTypeSupergraph,
		},
	))

	t.Run("should return adapter type proxy only for execution mode proxy only", run(
		testInput{
			executionMode:  apidef.GraphQLExecutionModeExecutionEngine,
			expectedResult: GraphQLEngineAdapterTypeUniversalDataGraph,
		},
	))
}
