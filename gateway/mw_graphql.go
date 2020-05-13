package gateway

import (
	"bytes"
	"encoding/json"
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
	SchemaDataSource   = "SchemaDataSource"
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
			TypeName:  "query",
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
			HttpClient: executionClient,
		}

		graphQLOptions := gql.DataSourceGraphqlOptions{
			HttpClient: executionClient,
		}

		err = engine.AddHttpJsonDataSourceWithOptions(HTTPJSONDataSource, httpJSONOptions)
		err = engine.AddGraphqlDataSourceWithOptions(GraphQLDataSource, graphQLOptions)
		err = engine.AddDataSource(SchemaDataSource, datasource.SchemaDataSourcePlannerFactoryFactory{})

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

type GraphQLResponseWriter struct {
	response *http.Response
}

func NewGraphQLResponseWriter() *GraphQLResponseWriter {
	return &GraphQLResponseWriter{
		response: &http.Response{
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			StatusCode: http.StatusOK,
		},
	}
}

func (g *GraphQLResponseWriter) GetHTTPResponse() *http.Response {
	return g.response
}

func (g *GraphQLResponseWriter) Header() http.Header {
	return g.response.Header
}

func (g *GraphQLResponseWriter) WriteHeader(statusCode int) {
	g.response.StatusCode = statusCode
}

func (g *GraphQLResponseWriter) Write(p []byte) (n int, err error) {
	buf := bytes.NewBuffer(p)
	err = g.response.Write(buf)
	return buf.Len(), err
}
