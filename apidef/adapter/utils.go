package adapter

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"sort"
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

func newApiDefinition(name, orgId string) *apidef.APIDefinition {
	return &apidef.APIDefinition{
		Name:   name,
		Active: true,
		OrgID:  orgId,
		APIID:  uuid.NewHex(),
		GraphQL: apidef.GraphQLConfig{
			Enabled:       true,
			Version:       apidef.GraphQLConfigVersion2,
			ExecutionMode: apidef.GraphQLExecutionModeExecutionEngine,
			Proxy: apidef.GraphQLProxyConfig{
				AuthHeaders: make(map[string]string),
			},
		},
		VersionDefinition: apidef.VersionDefinition{
			Enabled:  false,
			Location: "header",
		},
		VersionData: apidef.VersionData{
			NotVersioned: true,
			Versions: map[string]apidef.VersionInfo{
				"Default": {
					Name:             "Default",
					UseExtendedPaths: true,
				},
			},
		},
		Proxy: apidef.ProxyConfig{
			StripListenPath: true,
		},
	}
}

func sortFieldConfigsByName(apiDefinition *apidef.APIDefinition) {
	sort.Slice(apiDefinition.GraphQL.Engine.FieldConfigs, func(i, j int) bool {
		return apiDefinition.GraphQL.Engine.FieldConfigs[i].FieldName < apiDefinition.GraphQL.Engine.FieldConfigs[j].FieldName
	})
}

func sortDataSourcesByName(apiDefinition *apidef.APIDefinition) {
	sort.Slice(apiDefinition.GraphQL.Engine.DataSources, func(i, j int) bool {
		return apiDefinition.GraphQL.Engine.DataSources[i].Name < apiDefinition.GraphQL.Engine.DataSources[j].Name
	})
}
