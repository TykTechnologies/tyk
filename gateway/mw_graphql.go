package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/jensneuse/abstractlogger"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/headers"

	gql "github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

const (
	HTTPJSONDataSource = "HTTPJSONDataSource"
	GraphQLDataSource  = "GraphQLDataSource"
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
	schema, err := gql.NewSchemaFromString(m.Spec.GraphQL.GraphQLAPI.Schema)
	if err != nil {
		log.Errorf("Error while creating schema from API definition: %v", err)
	}

	m.Spec.GraphQLExecutor.Schema = schema

	if m.Spec.GraphQL.GraphQLAPI.Execution.Mode == apidef.GraphQLExecutionModeExecutionEngine {

		absLogger := abstractlogger.NewLogrusLogger(log, absLoggerLevel(log.Level))
		plannerConfig := datasource.PlannerConfiguration{
			TypeFieldConfigurations: m.Spec.GraphQL.GraphQLAPI.TypeFieldConfigurations,
		}

		engine, err := gql.NewExecutionEngine(absLogger, schema, plannerConfig)
		if err != nil {
			log.Errorf("GraphQL execution engine couldn't created: %v", err)
			return
		}

		executionClient := &http.Client{}

		httpJSONOptions := gql.DataSourceHttpJsonOptions{
			HttpClient: executionClient,
		}

		graphQLOptions := gql.DataSourceGraphqlOptions{
			HttpClient: executionClient,
		}

		err = engine.AddHttpJsonDataSourceWithOptions(HTTPJSONDataSource, httpJSONOptions)
		err = engine.AddGraphqlDataSourceWithOptions(GraphQLDataSource, graphQLOptions)

		m.Spec.GraphQLExecutor.Engine = engine
		m.Spec.GraphQLExecutor.Client = httpJSONOptions.HttpClient
	}
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	if m.Spec.GraphQLExecutor.Schema == nil {
		m.Logger().Error("Schema is not created")
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	var gqlRequest gql.Request
	err := gql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		m.Logger().Errorf("Error while unmarshalling GraphQL request: '%s'", err)
		return err, http.StatusBadRequest
	}

	defer ctxSetGraphQLRequest(r, &gqlRequest)

<<<<<<< HEAD
	normalizationResult, err := gqlRequest.Normalize(m.Spec.graphqlSchema)
	if err != nil {
		m.Logger().Errorf("Error while normalizing GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(m.Spec.graphqlSchema)
=======
	result, err := gqlRequest.ValidateForSchema(m.Spec.GraphQLExecutor.Schema)
>>>>>>> Implement GraphQL execution engine
	if err != nil {
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, validationResult.Errors)
	}

	return nil, http.StatusOK
}

<<<<<<< HEAD
func (m *GraphQLMiddleware) writeGraphQLError(w http.ResponseWriter, errors gql.Errors) (error, int) {
	w.Header().Set(headers.ContentType, headers.ApplicationJSON)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = errors.WriteResponse(w)
	m.Logger().Errorf("Error while validating GraphQL request: '%s'", errors)
	return errCustomBodyResponse, http.StatusBadRequest
=======
func absLoggerLevel(level logrus.Level) abstractlogger.Level {
	switch level {
	case logrus.ErrorLevel:
		return abstractlogger.ErrorLevel
	case logrus.WarnLevel:
		return abstractlogger.WarnLevel
	case logrus.DebugLevel:
		return abstractlogger.DebugLevel
	}
	return abstractlogger.InfoLevel
>>>>>>> Implement GraphQL execution engine
}
