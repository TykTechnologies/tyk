package adapter

import (
	"github.com/TykTechnologies/tyk/apidef"
)

type GraphQLEngineAdapterType int

const (
	GraphQLEngineAdapterTypeUnknown = iota
	GraphQLEngineAdapterTypeProxyOnly
	GraphQLEngineAdapterTypeSupergraph
	GraphQLEngineAdapterTypeUniversalDataGraph
)

func isSupergraphAPIDefinition(apiDefinition *apidef.APIDefinition) bool {
	return apiDefinition.GraphQL.Enabled && apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSupergraph
}

func isProxyOnlyAPIDefinition(apiDefinition *apidef.APIDefinition) bool {
	return apiDefinition.GraphQL.Enabled &&
		(apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly || apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeSubgraph)
}

func isUniversalDataGraphAPIDefinition(apiDefinition *apidef.APIDefinition) bool {
	return apiDefinition.GraphQL.Enabled && apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeExecutionEngine
}

func graphqlEngineAdapterTypeFromApiDefinition(apiDefinition *apidef.APIDefinition) GraphQLEngineAdapterType {
	if isProxyOnlyAPIDefinition(apiDefinition) {
		return GraphQLEngineAdapterTypeProxyOnly
	}

	if isSupergraphAPIDefinition(apiDefinition) {
		return GraphQLEngineAdapterTypeSupergraph
	}

	if isUniversalDataGraphAPIDefinition(apiDefinition) {
		return GraphQLEngineAdapterTypeUniversalDataGraph
	}

	return GraphQLEngineAdapterTypeUnknown
}
