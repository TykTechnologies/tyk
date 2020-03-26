package gateway

import (
	"errors"
	"net/http"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
)

type GraphQLMiddleware struct {
	BaseMiddleware
	Schema *gql.Schema
}

func (m *GraphQLMiddleware) Name() string {
	return "GraphQLMiddleware"
}

func (m *GraphQLMiddleware) EnabledForSpec() bool {
	return m.Spec.GraphQL.Enabled
}

func (m *GraphQLMiddleware) Init() {
	schema, err := gql.NewSchemaFromString(m.Spec.GraphQL.GraphQLAPI.Schema)
	if err != nil {
		log.Errorf("Error while creating schema from API definition: %v", err)
	}

	m.Schema = schema
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	if m.Schema == nil {
		return errors.New("schema is not created"), http.StatusInternalServerError
	}

	return nil, http.StatusOK
}
