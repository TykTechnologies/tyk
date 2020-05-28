package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/jensneuse/abstractlogger"
	"github.com/jensneuse/graphql-go-tools/pkg/execution/datasource"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/headers"

	gql "github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

const (
	HTTPJSONDataSource   = "HTTPJSONDataSource"
	GraphQLDataSource    = "GraphQLDataSource"
	SchemaDataSource     = "SchemaDataSource"
	TykRESTDataSource    = "TykRESTDataSource"
	TykGraphQLDataSource = "TykGraphQLDataSource"
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

		typeFieldConfigurations := m.Spec.GraphQL.GraphQLAPI.TypeFieldConfigurations
		typeFieldConfigurations = append(typeFieldConfigurations, datasource.TypeFieldConfiguration{
			TypeName:  "Query",
			FieldName: "__schema",
			DataSource: datasource.SourceConfig{
				Name: SchemaDataSource,
				Config: func() json.RawMessage {
					res, _ := json.Marshal(datasource.SchemaDataSourcePlannerConfig{})
					return res
				}(),
			},
		})

		absLogger := abstractlogger.NewLogrusLogger(log, absLoggerLevel(log.Level))
		plannerConfig := datasource.PlannerConfiguration{
			TypeFieldConfigurations: typeFieldConfigurations,
		}

		engine, err := gql.NewExecutionEngine(absLogger, schema, plannerConfig)
		if err != nil {
			log.Errorf("GraphQL execution engine couldn't created: %v", err)
			return
		}

		executionClient := &http.Client{}

		httpJSONOptions := gql.DataSourceHttpJsonOptions{
			HttpClient:         executionClient,
			WhitelistedSchemes: []string{"tyk"},
		}

		graphQLOptions := gql.DataSourceGraphqlOptions{
			HttpClient:         executionClient,
			WhitelistedSchemes: []string{"tyk"},
		}

		errMsgFormat := "%s couldn't be added"

		err = engine.AddHttpJsonDataSourceWithOptions(HTTPJSONDataSource, httpJSONOptions)
		if err != nil {
			m.Logger().WithError(err).Errorf(errMsgFormat, HTTPJSONDataSource)
		}

		err = engine.AddHttpJsonDataSourceWithOptions(TykRESTDataSource, httpJSONOptions)
		if err != nil {
			m.Logger().WithError(err).Errorf(errMsgFormat, HTTPJSONDataSource)
		}

		err = engine.AddGraphqlDataSourceWithOptions(GraphQLDataSource, graphQLOptions)
		if err != nil {
			m.Logger().WithError(err).Errorf(errMsgFormat, GraphQLDataSource)
		}

		err = engine.AddGraphqlDataSourceWithOptions(TykGraphQLDataSource, graphQLOptions)
		if err != nil {
			m.Logger().WithError(err).Errorf(errMsgFormat, GraphQLDataSource)
		}

		err = engine.AddDataSource(SchemaDataSource, datasource.SchemaDataSourcePlannerFactoryFactory{})
		if err != nil {
			m.Logger().WithError(err).Errorf(errMsgFormat, SchemaDataSource)
		}

		m.Spec.GraphQLExecutor.Engine = engine
		m.Spec.GraphQLExecutor.Client = httpJSONOptions.HttpClient
	}
}

func (m *GraphQLMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	if m.Spec.GraphQLExecutor.Schema == nil {
		m.Logger().Error("Schema is not created")
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		m.Logger().Errorf("Could not read body data: '%s'", err)
	}

	var gqlRequest gql.Request
	err = gql.UnmarshalRequest(bytes.NewReader(bodyBytes), &gqlRequest)
	if err != nil {
		m.Logger().Errorf("Error while unmarshalling GraphQL request: '%s'", err)
		return err, http.StatusBadRequest
	}

	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	defer ctxSetGraphQLRequest(r, &gqlRequest)

	normalizationResult, err := gqlRequest.Normalize(m.Spec.GraphQLExecutor.Schema)
	if err != nil {
		m.Logger().Errorf("Error while normalizing GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(m.Spec.GraphQLExecutor.Schema)
	if err != nil {
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return m.writeGraphQLError(w, validationResult.Errors)
	}

	return nil, http.StatusOK
}

func (m *GraphQLMiddleware) writeGraphQLError(w http.ResponseWriter, errors gql.Errors) (error, int) {
	w.Header().Set(headers.ContentType, headers.ApplicationJSON)
	w.WriteHeader(http.StatusBadRequest)
	_, _ = errors.WriteResponse(w)
	m.Logger().Errorf("Error while validating GraphQL request: '%s'", errors)
	return errCustomBodyResponse, http.StatusBadRequest
}

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
}
