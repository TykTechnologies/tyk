package graphengine

import (
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/otel"
)

type EngineV1 struct {
	ExecutionEngine    *graphql.ExecutionEngine
	Schema             *graphql.Schema
	ApiDefinition      *apidef.APIDefinition
	HttpClient         *http.Client
	OTelConfig         otel.OpenTelemetry
	OTelTracerProvider otel.TracerProvider

	logger                  *abstractlogger.LogrusLogger
	gqlTools                graphqlGoToolsV1
	graphqlRequestProcessor GraphQLRequestProcessor
	complexityChecker       ComplexityChecker
	granularAccessChecker   GranularAccessChecker
	ctxStoreRequestFunc     func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc  func(r *http.Request) *graphql.Request
}

type EngineV1Options struct {
	Logger                 *logrus.Logger
	ApiDefinition          *apidef.APIDefinition
	HttpClient             *http.Client
	OTelConfig             otel.OpenTelemetry
	OTelTracerProvider     otel.TracerProvider
	PreSendHttpHook        datasource.PreSendHttpHook
	PostReceiveHttpHook    datasource.PostReceiveHttpHook
	ContextStoreRequest    contextStoreRequestV1Func
	ContextRetrieveRequest contextRetrieveRequestV1Func
}

func NewEngineV1(options EngineV1Options) (*EngineV1, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	gqlTools := graphqlGoToolsV1{}

	parsedSchema, err := gqlTools.parseSchema(options.ApiDefinition.GraphQL.Schema)
	if err != nil {
		logger.Error("error on schema parsing", abstractlogger.Error(err))
		return nil, err
	}

	executionEngine, err := gqlTools.createExecutionEngine(createExecutionEngineV1Params{
		apiDef:              options.ApiDefinition,
		schema:              parsedSchema,
		httpClient:          options.HttpClient,
		preSendHttpHook:     options.PreSendHttpHook,
		postReceiveHttpHook: options.PostReceiveHttpHook,
	})
	if err != nil {
		logger.Error("error on execution engine creation", abstractlogger.Error(err))
		return nil, err
	}

	requestProcessor := graphqlRequestProcessorV1{
		logger:             logger,
		schema:             parsedSchema,
		ctxRetrieveRequest: options.ContextRetrieveRequest,
	}

	complexityChecker := &complexityCheckerV1{
		logger:             logger,
		schema:             parsedSchema,
		ctxRetrieveRequest: options.ContextRetrieveRequest,
	}

	granularAccessChecker := &granularAccessCheckerV1{
		logger:                    logger,
		schema:                    parsedSchema,
		ctxRetrieveGraphQLRequest: options.ContextRetrieveRequest,
	}

	return &EngineV1{
		ExecutionEngine:         executionEngine,
		Schema:                  parsedSchema,
		ApiDefinition:           options.ApiDefinition,
		HttpClient:              options.HttpClient,
		OTelConfig:              options.OTelConfig,
		OTelTracerProvider:      options.OTelTracerProvider,
		logger:                  logger,
		gqlTools:                gqlTools,
		graphqlRequestProcessor: &requestProcessor,
		complexityChecker:       complexityChecker,
		granularAccessChecker:   granularAccessChecker,
		ctxStoreRequestFunc:     options.ContextStoreRequest,
		ctxRetrieveRequestFunc:  options.ContextRetrieveRequest,
	}, nil
}

func (e *EngineV1) HasSchema() bool {
	return e.Schema != nil
}

func (e *EngineV1) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphql.Request
	err = graphql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		//m.Logger().Debugf("Error while unmarshalling GraphQL request: '%s'", err)
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	defer e.ctxStoreRequestFunc(r, &gqlRequest)
	if e.OTelConfig.Enabled && e.ApiDefinition.DetailedTracing {
		// REMOVE FOR V1
		/*ctx, span := e.OTelTracerProvider.Tracer().Start(r.Context(), "GraphqlMiddleware Validation")
		defer span.End()
		*r = *r.WithContext(ctx)
		//return e.gqlTools.validateRequestWithOtel(r.Context(), w, &gqlRequest)
		return e.gqlTools.validateRequestWithOtel(validateRequestWithOtelV1Params{
			logger:       e.logger,
			ctx:          r.Context(),
			w:            w,
			gqlRequest:   &gqlRequest,
			otelExecutor: nil,
		})*/
		// END REMOVE FOR v1
	}

	return e.graphqlRequestProcessor.ProcessRequest(r.Context(), w, r)
}

func (e *EngineV1) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	return complexityFailReasonAsHttpStatusCode(e.complexityChecker.DepthLimitExceeded(r, accessDefinition))
}

func (e *EngineV1) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	result := e.granularAccessChecker.CheckGraphQLRequestFieldAllowance(w, r, accessDefinition)
	return granularAccessFailReasonAsHttpStatusCode(e.logger, &result, w)
}

func (e *EngineV1) HandleReverseProxy(roundTripper http.RoundTripper, w http.ResponseWriter, r *http.Request) (res *http.Response, err error) {
	return nil, nil
}

// Interface Guard
var _ Engine = (*EngineV1)(nil)
