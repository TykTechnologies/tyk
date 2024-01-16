package graphengine

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter"
	graphqlinternal "github.com/TykTechnologies/tyk/internal/graphql"
	"github.com/TykTechnologies/tyk/internal/otel"
)

type EngineV2OTelConfig struct {
	Enabled        bool
	Config         otel.OpenTelemetry
	TracerProvider otel.TracerProvider
	Executor       graphqlinternal.TykOtelExecutorI
}

type EngineV2 struct {
	ExecutionEngine *graphql.ExecutionEngineV2
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   *EngineV2OTelConfig

	logger                  abstractlogger.Logger
	gqlTools                graphqlGoToolsV1
	graphqlRequestProcessor GraphQLRequestProcessor
	complexityChecker       ComplexityChecker
	granularAccessChecker   GranularAccessChecker
	reverseProxyPreHandler  ReverseProxyPreHandler
	contextCancel           context.CancelFunc
	beforeFetchHook         resolve.BeforeFetchHook
	afterFetchHook          resolve.AfterFetchHook
	ctxStoreRequestFunc     func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc  func(r *http.Request) *graphql.Request
	engineTransportModifier TransportModifier
}

type EngineV2Options struct {
	Logger                  *logrus.Logger
	ApiDefinition           *apidef.APIDefinition
	HttpClient              *http.Client
	StreamingClient         *http.Client
	OpenTelemetry           *EngineV2OTelConfig
	BeforeFetchHook         resolve.BeforeFetchHook
	AfterFetchHook          resolve.AfterFetchHook
	WebsocketOnBeforeStart  graphql.WebsocketBeforeStartHook
	ContextStoreRequest     ContextStoreRequestV1Func
	ContextRetrieveRequest  ContextRetrieveRequestV1Func
	EngineTransportModifier TransportModifier
}

func NewEngineV2(options EngineV2Options) (*EngineV2, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	gqlTools := graphqlGoToolsV1{}

	parsedSchema, err := gqlTools.parseSchema(options.ApiDefinition.GraphQL.Schema)
	if err != nil {
		logger.Error("error on schema parsing", abstractlogger.Error(err))
		return nil, err
	}

	configAdapter := adapter.NewGraphQLConfigAdapter(options.ApiDefinition,
		adapter.WithHttpClient(options.HttpClient),
		adapter.WithStreamingClient(options.StreamingClient),
		adapter.WithSchema(parsedSchema),
	)

	engineConfig, err := configAdapter.EngineConfigV2()
	if err != nil {
		options.Logger.WithError(err).Error("could not create engine v2 config")
		return nil, err
	}
	engineConfig.SetWebsocketBeforeStartHook(options.WebsocketOnBeforeStart)
	specCtx, cancel := context.WithCancel(context.Background())

	executionEngine, err := graphql.NewExecutionEngineV2(specCtx, logger, *engineConfig)
	if err != nil {
		options.Logger.WithError(err).Error("could not create execution engine v2")
		cancel()
		return nil, err
	}

	requestProcessor := &graphqlRequestProcessorV1{
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

	reverseProxyPreHandler := &reverseProxyPreHandlerV1{
		ctxRetrieveGraphQLRequest: options.ContextRetrieveRequest,
		apiDefinition:             options.ApiDefinition,
		httpClient:                options.HttpClient,
		transportModifier:         options.EngineTransportModifier,
	}

	engineV2 := &EngineV2{
		ExecutionEngine:         executionEngine,
		Schema:                  parsedSchema,
		ApiDefinition:           options.ApiDefinition,
		HttpClient:              options.HttpClient,
		StreamingClient:         options.StreamingClient,
		OpenTelemetry:           options.OpenTelemetry,
		logger:                  logger,
		gqlTools:                gqlTools,
		graphqlRequestProcessor: requestProcessor,
		complexityChecker:       complexityChecker,
		granularAccessChecker:   granularAccessChecker,
		reverseProxyPreHandler:  reverseProxyPreHandler,
		contextCancel:           cancel,
		beforeFetchHook:         options.BeforeFetchHook,
		afterFetchHook:          options.AfterFetchHook,
		ctxStoreRequestFunc:     options.ContextStoreRequest,
		ctxRetrieveRequestFunc:  options.ContextRetrieveRequest,
		engineTransportModifier: options.EngineTransportModifier,
	}

	if engineV2.OpenTelemetry == nil {
		engineV2.OpenTelemetry = &EngineV2OTelConfig{}
	}

	if options.OpenTelemetry.Enabled {
		var executor graphqlinternal.TykOtelExecutorI
		if options.ApiDefinition.DetailedTracing {
			executor, err = graphqlinternal.NewOtelGraphqlEngineV2Detailed(options.OpenTelemetry.TracerProvider, executionEngine)
		} else {
			executor, err = graphqlinternal.NewOtelGraphqlEngineV2Basic(options.OpenTelemetry.TracerProvider, executionEngine)
		}
		if err != nil {
			options.Logger.WithError(err).Error("error creating custom execution engine v2")
			cancel()
			return nil, err
		}

		otelRequestProcessor := &graphqlRequestProcessorWithOTelV1{
			logger:             logger,
			schema:             parsedSchema,
			otelExecutor:       executor,
			ctxRetrieveRequest: options.ContextRetrieveRequest,
		}
		engineV2.graphqlRequestProcessor = otelRequestProcessor
		engineV2.OpenTelemetry.Executor = executor
	}

	if isSupergraphAPIDefinition(options.ApiDefinition) {
		engineV2.ApiDefinition.GraphQL.Schema = engineV2.ApiDefinition.GraphQL.Supergraph.MergedSDL
	}

	return engineV2, nil
}

func (e EngineV2) HasSchema() bool {
	return e.Schema != nil
}

func (e EngineV2) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphql.Request
	err = graphql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	defer e.ctxStoreRequestFunc(r, &gqlRequest)
	if e.OpenTelemetry.Enabled && e.ApiDefinition.DetailedTracing {
		ctx, span := e.OpenTelemetry.TracerProvider.Tracer().Start(r.Context(), "GraphqlMiddleware Validation")
		defer span.End()
		*r = *r.WithContext(ctx)
	}

	return e.graphqlRequestProcessor.ProcessRequest(r.Context(), w, r)
}

func (e EngineV2) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	return complexityFailReasonAsHttpStatusCode(e.complexityChecker.DepthLimitExceeded(r, accessDefinition))
}

func (e EngineV2) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	result := e.granularAccessChecker.CheckGraphQLRequestFieldAllowance(w, r, accessDefinition)
	return granularAccessFailReasonAsHttpStatusCode(e.logger, &result, w)
}

func (e EngineV2) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	//TODO implement me
	panic("implement me")
}

// Interface Guard
var _ Engine = (*EngineV2)(nil)
