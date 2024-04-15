package graphengine

import (
	"context"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/adapter"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
	"net/http"
)

type EngineV3 struct {
	engine         *graphql.ExecutionEngineV2
	schema         *graphql.Schema
	logger         abstractlogger.Logger
	openTelemetry  *EngineV2OTelConfig
	apiDefinitions *apidef.APIDefinition

	ctxStoreRequestFunc    ContextStoreRequestV2Func
	ctxRetrieveRequestFunc ContextRetrieveRequestV2Func

	gqlTools                  graphqlGoToolsV2
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	contextCancel             context.CancelFunc
	beforeFetchHook           resolve.BeforeFetchHook
	afterFetchHook            resolve.AfterFetchHook
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	seekReadCloser            SeekReadCloserFunc
	tykVariableReplacer       TykVariableReplacer
}

type EngineV3Injections struct {
	//BeforeFetchHook           resolve.BeforeFetchHook
	//AfterFetchHook            resolve.AfterFetchHook
	WebsocketOnBeforeStart    graphql.WebsocketBeforeStartHook
	ContextStoreRequest       ContextStoreRequestV2Func
	ContextRetrieveRequest    ContextRetrieveRequestV2Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}

type EngineV3Options struct {
	Logger          *logrus.Logger
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   EngineV2OTelConfig
	Injections      EngineV3Injections
}

func NewEngineV3(options EngineV3Options) (*EngineV3, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	//gqlTools := graphqlGoToolsV2{}

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
	//specCtx, cancel := context.WithCancel(context.Background())

	//executionEngine, err := graphql.NewExecutionEngineV2(specCtx, logger, *engineConfig)
	//if err != nil {
	//	options.Logger.WithError(err).Error("could not create execution engine v2")
	//	cancel()
	//	return nil, err
	//}
	//
	//requestProcessor := &graphqlRequestProcessorV1{
	//	logger:             logger,
	//	schema:             parsedSchema,
	//	ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	//}
	//
	//complexityChecker := &complexityCheckerV1{
	//	logger:             logger,
	//	schema:             parsedSchema,
	//	ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	//}
	//
	//granularAccessChecker := &granularAccessCheckerV1{
	//	logger:                    logger,
	//	schema:                    parsedSchema,
	//	ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
	//}
	//
	//reverseProxyPreHandler := &reverseProxyPreHandlerV1{
	//	ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
	//	apiDefinition:             options.ApiDefinition,
	//	httpClient:                options.HttpClient,
	//	newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
	//}

	engine := EngineV3{
		logger:                 logger,
		schema:                 options.Schema,
		ctxRetrieveRequestFunc: options.Injections.ContextRetrieveRequest,
		ctxStoreRequestFunc:    options.Injections.ContextStoreRequest,
		openTelemetry:          &options.OpenTelemetry,
		apiDefinitions:         options.ApiDefinition,
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
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphql.Request
	err = graphql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	e.ctxStoreRequestFunc(r, &gqlRequest)
	if e.openTelemetry.Enabled && e.apiDefinitions.DetailedTracing {
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

	v1Request := e.ctxRetrieveRequestFunc(r)
	gqlRequest := graphql.Request{
		Variables:     v1Request.Variables,
		Query:         v1Request.Query,
		OperationName: v1Request.OperationName,
	}
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
func (e *EngineV3) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	//TODO implement me
	panic("implement me")
}
