package graphengine

import (
	"context"
	"net/http"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter"
	graphqlinternal "github.com/TykTechnologies/tyk/internal/graphql"
)

type EngineV3 struct {
	engine        *graphqlv2.ExecutionEngineV2
	schema        *graphqlv2.Schema
	logger        abstractlogger.Logger
	openTelemetry *EngineV2OTelConfig
	apiDefinition *apidef.APIDefinition

	ctxStoreRequestFunc    ContextStoreRequestV2Func
	ctxRetrieveRequestFunc ContextRetrieveRequestV2Func

	gqlTools                  graphqlGoToolsV2
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	contextCancel             context.CancelFunc
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	seekReadCloser            SeekReadCloserFunc
	tykVariableReplacer       TykVariableReplacer
}

type EngineV3Injections struct {
	WebsocketOnBeforeStart    graphqlv2.WebsocketBeforeStartHook
	ContextStoreRequest       ContextStoreRequestV2Func
	ContextRetrieveRequest    ContextRetrieveRequestV2Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}

type EngineV3Options struct {
	Logger          *logrus.Logger
	Schema          *graphqlv2.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   EngineV2OTelConfig
	Injections      EngineV3Injections
}

func NewEngineV3(options EngineV3Options) (*EngineV3, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	gqlTools := graphqlGoToolsV2{}

	var parsedSchema = options.Schema
	if parsedSchema == nil {
		var err error
		parsedSchema, err = gqlTools.parseSchema(options.ApiDefinition.GraphQL.Schema)
		if err != nil {
			logger.Error("error on schema parsing", abstractlogger.Error(err))
			return nil, err
		}
	}

	// TODO check the streaming client usage here
	configAdapter := adapter.NewGraphQLConfigAdapter(options.ApiDefinition,
		adapter.WithHttpClient(options.HttpClient),
		adapter.WithV2Schema(options.Schema),
		adapter.WithStreamingClient(options.StreamingClient),
	)

	engineConfig, err := configAdapter.EngineConfigV3()
	if err != nil {
		options.Logger.WithError(err).Error("could not create engine v2 config")
		return nil, err
	}
	engineConfig.SetWebsocketBeforeStartHook(options.Injections.WebsocketOnBeforeStart)
	specCtx, cancel := context.WithCancel(context.Background())

	executionEngine, err := graphqlv2.NewExecutionEngineV2(specCtx, logger, *engineConfig)
	if err != nil {
		options.Logger.WithError(err).Error("could not create execution engine v2")
		cancel()
		return nil, err
	}
	//
	//requestProcessor := &graphqlRequestProcessorV1{
	//	logger:             logger,
	//	schema:             parsedSchema,
	//	ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	//}
	//
	complexityChecker := &complexityCheckerV2{
		logger:             logger,
		schema:             parsedSchema,
		ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	}

	granularAccessChecker := &granularAccessCheckerV2{
		logger:                    logger,
		schema:                    parsedSchema,
		ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
	}

	reverseProxyPreHandler := &reverseProxyPreHandlerV2{
		ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
		apiDefinition:             options.ApiDefinition,
		httpClient:                options.HttpClient,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
	}

	engine := EngineV3{
		logger:                 logger,
		schema:                 options.Schema,
		engine:                 executionEngine,
		ctxRetrieveRequestFunc: options.Injections.ContextRetrieveRequest,
		ctxStoreRequestFunc:    options.Injections.ContextStoreRequest,
		openTelemetry:          &options.OpenTelemetry,
		apiDefinition:          options.ApiDefinition,
		reverseProxyPreHandler: reverseProxyPreHandler,
		gqlTools:               gqlTools,
		tykVariableReplacer:    options.Injections.TykVariableReplacer,
		seekReadCloser:         options.Injections.SeekReadCloser,
		contextCancel:          cancel,
		complexityChecker:      complexityChecker,
		granularAccessChecker:  granularAccessChecker,
	}

	if engine.openTelemetry == nil {
		engine.openTelemetry = &EngineV2OTelConfig{}
	}

	if engine.openTelemetry.Enabled {
		var executor graphqlinternal.TykOtelExecutorI
		if options.ApiDefinition.DetailedTracing {
			//executor, err = graphqlinternal.NewOtelGraphqlEngineV2Detailed(engine.openTelemetry.TracerProvider, executionEngine, parsedSchema)
		} else {
			//executor, err = graphqlinternal.NewOtelGraphqlEngineV2Basic(engine.openTelemetry.TracerProvider, executionEngine)
		}
		if err != nil {
			options.Logger.WithError(err).Error("error creating custom execution engine v2")
			cancel()
			return nil, err
		}

		otelRequestProcessor := &graphqlRequestProcessorWithOTelV1{
			logger: logger,
			//schema:             parsedSchema,
			otelExecutor: executor,
			//ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
		}
		engine.graphqlRequestProcessor = otelRequestProcessor
		engine.openTelemetry.Executor = executor
	}

	if isSupergraph(options.ApiDefinition) {
		engine.apiDefinition.GraphQL.Schema = engine.apiDefinition.GraphQL.Supergraph.MergedSDL
	}

	return &engine, nil
}

func (e *EngineV3) Version() EngineVersion {
	return EngineVersionV3
}

func (e *EngineV3) HasSchema() bool {
	return e.schema != nil
}

func (e *EngineV3) Cancel() {
	if e.contextCancel != nil {
		e.contextCancel()
	}
}

func (e *EngineV3) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphqlv2.Request
	err = graphqlv2.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	e.ctxStoreRequestFunc(r, &gqlRequest)
	if e.openTelemetry.Enabled && e.apiDefinition.DetailedTracing {
		ctx, span := e.openTelemetry.TracerProvider.Tracer().Start(r.Context(), "GraphqlMiddleware Validation")
		defer span.End()
		*r = *r.WithContext(ctx)
	}

	return e.ProcessRequest(r.Context(), w, r)
}

func (e *EngineV3) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
	if r == nil {
		e.logger.Error("request is nil")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	gqlRequest := e.ctxRetrieveRequestFunc(r)
	normalizationResult, err := gqlRequest.Normalize(e.schema)
	if err != nil {
		e.logger.Error("error while normalizing GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return writeGraphQLError(e.logger, w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(e.schema)
	if err != nil {
		e.logger.Error("error while validating GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return writeGraphQLError(e.logger, w, validationResult.Errors)
	}

	inputValidationResult, err := gqlRequest.ValidateInput(e.schema)
	if err != nil {
		e.logger.Error("error while validating variables for request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	if inputValidationResult.Errors != nil && inputValidationResult.Errors.Count() > 0 {
		return writeGraphQLError(e.logger, w, inputValidationResult.Errors)
	}
	return nil, http.StatusOK
}
