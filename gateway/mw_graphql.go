package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/headers"

	gql "github.com/jensneuse/graphql-go-tools/pkg/graphql"
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
		m.Logger().Error("Schema is not created")
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	var gqlRequest gql.Request
	err := gql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		m.Logger().Errorf("Error while unmarshalling GraphQL request: '%s'", err)
		return err, http.StatusBadRequest
	}

	result, err := gqlRequest.ValidateForSchema(m.Schema)
	if err != nil {
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if result.Errors != nil && result.Errors.Count() > 0 {
		w.Header().Set(headers.ContentType, headers.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = result.Errors.WriteResponse(w)
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", result.Errors)
		return errCustomBodyResponse, http.StatusBadRequest
	}

	session := ctxGetSession(r)
	if session == nil {
		return nil, http.StatusOK
	}

	complexityRes, err := gqlRequest.CalculateComplexity(gql.DefaultComplexityCalculator, m.Schema)
	if err != nil {
		m.Logger().Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if session.MaxQueryDepth != disabledQueryDepth && complexityRes.Depth > session.MaxQueryDepth {
		m.Logger().Errorf("Complexity of the request is higher than the allowed limit '%d'", session.MaxQueryDepth)
		return errors.New("depth limit exceeded"), http.StatusForbidden
	}

	return nil, http.StatusOK
}
