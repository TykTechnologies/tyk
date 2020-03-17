package gateway

import (
	"net/http"
)

type GraphQLMiddleware struct {
	BaseMiddleware
}

func (m *GraphQLMiddleware) Name() string {
	return "GraphQLMiddleware"
}

func (m *GraphQLMiddleware) EnabledForSpec() bool {
	for _, versionData := range m.Spec.VersionData.Versions {
		if versionData.GraphQL.GraphQLApi.Schema != "" {
			return true
		}
	}

	return false
}

func (m *GraphQLMiddleware) Init() {
	logger := m.Logger()
	logger.Info("I'm loaded")

	if m.Spec.graphQLSchema == nil {
	}
}

func (m *GraphQLMiddleware) Destructor() {
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	logger := m.Logger()
	logger.Info("I'm loaded")

	return nil, http.StatusOK
}
