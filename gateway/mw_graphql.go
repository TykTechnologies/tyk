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
	return m.Spec.GraphQL.Enabled
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
