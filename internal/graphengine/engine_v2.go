package graphengine

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/datasource/httpclient"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/subscription"
	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"

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

type EngineV2Injections struct {
	BeforeFetchHook           resolve.BeforeFetchHook
	AfterFetchHook            resolve.AfterFetchHook
	WebsocketOnBeforeStart    graphql.WebsocketBeforeStartHook
	ContextStoreRequest       ContextStoreRequestV1Func
	ContextRetrieveRequest    ContextRetrieveRequestV1Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}

type EngineV2 struct {
	ExecutionEngine *graphql.ExecutionEngineV2
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   *EngineV2OTelConfig

	logger                    abstractlogger.Logger
	gqlTools                  graphqlGoToolsV1
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	contextCancel             context.CancelFunc
	beforeFetchHook           resolve.BeforeFetchHook
	afterFetchHook            resolve.AfterFetchHook
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	seekReadCloser            SeekReadCloserFunc
	tykVariableReplacer       TykVariableReplacer
}

type EngineV2Options struct {
	Logger          *logrus.Logger
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   EngineV2OTelConfig
	Injections      EngineV2Injections
}

func NewEngineV2(options EngineV2Options) (*EngineV2, error) {
	logger := createAbstractLogrusLogger(options.Logger)
	gqlTools := graphqlGoToolsV1{}

	var parsedSchema = options.Schema
	if parsedSchema == nil {
		var err error
		parsedSchema, err = gqlTools.parseSchema(options.ApiDefinition.GraphQL.Schema)
		if err != nil {
			logger.Error("error on schema parsing", abstractlogger.Error(err))
			return nil, err
		}
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
	engineConfig.SetWebsocketBeforeStartHook(options.Injections.WebsocketOnBeforeStart)
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
		ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	}

	complexityChecker := &complexityCheckerV1{
		logger:             logger,
		schema:             parsedSchema,
		ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	}

	granularAccessChecker := &granularAccessCheckerV1{
		logger:                    logger,
		schema:                    parsedSchema,
		ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
	}

	reverseProxyPreHandler := &reverseProxyPreHandlerV1{
		ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
		apiDefinition:             options.ApiDefinition,
		httpClient:                options.HttpClient,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
	}

	engineV2 := &EngineV2{
		ExecutionEngine:           executionEngine,
		Schema:                    parsedSchema,
		ApiDefinition:             options.ApiDefinition,
		HttpClient:                options.HttpClient,
		StreamingClient:           options.StreamingClient,
		OpenTelemetry:             &options.OpenTelemetry,
		logger:                    logger,
		gqlTools:                  gqlTools,
		graphqlRequestProcessor:   requestProcessor,
		complexityChecker:         complexityChecker,
		granularAccessChecker:     granularAccessChecker,
		reverseProxyPreHandler:    reverseProxyPreHandler,
		contextCancel:             cancel,
		beforeFetchHook:           options.Injections.BeforeFetchHook,
		afterFetchHook:            options.Injections.AfterFetchHook,
		ctxStoreRequestFunc:       options.Injections.ContextStoreRequest,
		ctxRetrieveRequestFunc:    options.Injections.ContextRetrieveRequest,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
		seekReadCloser:            options.Injections.SeekReadCloser,
		tykVariableReplacer:       options.Injections.TykVariableReplacer,
	}

	if engineV2.OpenTelemetry == nil {
		engineV2.OpenTelemetry = &EngineV2OTelConfig{}
	}

	if engineV2.OpenTelemetry.Enabled {
		var executor graphqlinternal.TykOtelExecutorI
		if options.ApiDefinition.DetailedTracing {
			executor, err = graphqlinternal.NewOtelGraphqlEngineV2Detailed(engineV2.OpenTelemetry.TracerProvider, executionEngine, parsedSchema)
		} else {
			executor, err = graphqlinternal.NewOtelGraphqlEngineV2Basic(engineV2.OpenTelemetry.TracerProvider, executionEngine)
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
			ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
		}
		engineV2.graphqlRequestProcessor = otelRequestProcessor
		engineV2.OpenTelemetry.Executor = executor
	}

	if isSupergraph(options.ApiDefinition) {
		engineV2.ApiDefinition.GraphQL.Schema = engineV2.ApiDefinition.GraphQL.Supergraph.MergedSDL
	}

	return engineV2, nil
}

func (e *EngineV2) Version() EngineVersion {
	return EngineVersionV2
}

func (e *EngineV2) HasSchema() bool {
	return e.Schema != nil
}

func (e *EngineV2) Cancel() {
	if e.contextCancel != nil {
		e.contextCancel()
	}
}

func (e *EngineV2) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphql.Request
	err = graphql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	e.ctxStoreRequestFunc(r, &gqlRequest)
	if e.OpenTelemetry.Enabled && e.ApiDefinition.DetailedTracing {
		ctx, span := e.OpenTelemetry.TracerProvider.Tracer().Start(r.Context(), "GraphqlMiddleware Validation")
		defer span.End()
		*r = *r.WithContext(ctx)
	}

	return e.graphqlRequestProcessor.ProcessRequest(r.Context(), w, r)
}

func (e *EngineV2) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	return complexityFailReasonAsHttpStatusCode(e.complexityChecker.DepthLimitExceeded(r, accessDefinition))
}

func (e *EngineV2) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	result := e.granularAccessChecker.CheckGraphQLRequestFieldAllowance(w, r, accessDefinition)
	return granularAccessFailReasonAsHttpStatusCode(e.logger, &result, w)
}

func (e *EngineV2) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	reverseProxyType, err := e.reverseProxyPreHandler.PreHandle(params)
	if err != nil {
		e.logger.Error("error on reverse proxy pre handler", abstractlogger.Error(err))
		return nil, false, err
	}

	switch reverseProxyType {
	case ReverseProxyTypeIntrospection:
		return e.gqlTools.handleIntrospection(e.Schema)
	case ReverseProxyTypeWebsocketUpgrade:
		return e.handoverWebSocketConnectionToGraphQLExecutionEngine(&params)
	case ReverseProxyTypeGraphEngine:
		gqlRequest := e.ctxRetrieveRequestFunc(params.OutRequest)
		// Cleanup method, frees allocated resources, if they are eligible for freeing up.
		// Currently, it only frees up the allocated resources of a GraphQL query that
		// has a cached query plan.
		//
		// graphql-go-tools uses the parsed query (ast.Document in graphql-go-tools codebase)
		// in the planner and caches the plans. If a plan has been cached, we can reset the created
		// ast.Document struct and put it back to the pool for later use. By this way, we can reduce the GC
		// pressure and number of allocations per GraphQL query.
		// See TT-9864 for the details.
		defer gqlRequest.Cleanup()
		return e.handoverRequestToGraphQLExecutionEngine(gqlRequest, params.OutRequest)
	case ReverseProxyTypePreFlight:
		if e.ApiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly {
			return nil, false, nil
		}
		return nil, false, errors.New("options passthrough not allowed")
	case ReverseProxyTypeNone:
		return nil, false, nil
	}

	e.logger.Error("unknown reverse proxy type", abstractlogger.Int("reverseProxyType", int(reverseProxyType)))
	return nil, false, ErrUnknownReverseProxyType
}

func (e *EngineV2) handoverRequestToGraphQLExecutionEngine(gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	if e.ExecutionEngine == nil {
		err = errors.New("execution engine is nil")
		return
	}

	isProxyOnly := isProxyOnly(e.ApiDefinition)
	span := otel.SpanFromContext(outreq.Context())
	reqCtx := otel.ContextWithSpan(context.Background(), span)
	if isProxyOnly {
		reqCtx = SetProxyOnlyContextValue(reqCtx, outreq)
	}

	resultWriter := graphql.NewEngineResultWriter()
	execOptions := []graphql.ExecutionOptionsV2{
		graphql.WithBeforeFetchHook(e.beforeFetchHook),
		graphql.WithAfterFetchHook(e.afterFetchHook),
	}

	upstreamHeaders := additionalUpstreamHeaders(e.logger, outreq, e.ApiDefinition)
	execOptions = append(execOptions, graphql.WithHeaderModifier(e.gqlTools.headerModifier(upstreamHeaders)))

	if e.OpenTelemetry.Executor != nil {
		if err = e.OpenTelemetry.Executor.Execute(reqCtx, gqlRequest, &resultWriter, execOptions...); err != nil {
			return
		}
	} else {
		err = e.ExecutionEngine.Execute(reqCtx, gqlRequest, &resultWriter, execOptions...)
		if err != nil {
			return
		}
	}

	httpStatus := http.StatusOK
	header := make(http.Header)
	header.Set("Content-Type", "application/json")

	if isProxyOnly {
		proxyOnlyCtx := GetProxyOnlyContextValue(reqCtx)
		// There is a case in the proxy-only mode where the request can be handled
		// by the library without calling the upstream.
		// This is a valid query for proxy-only mode: query { __typename }
		// In this case, upstreamResponse is nil.
		// See TT-6419 for further info.
		if proxyOnlyCtx.upstreamResponse != nil {
			header = proxyOnlyCtx.upstreamResponse.Header
			httpStatus = proxyOnlyCtx.upstreamResponse.StatusCode
			// change the value of the header's content encoding to use the content encoding defined by the accept encoding
			contentEncoding := selectContentEncodingToBeUsed(proxyOnlyCtx.forwardedRequest.Header.Get(httpclient.AcceptEncodingHeader))
			header.Set(httpclient.ContentEncodingHeader, contentEncoding)
			if e.ApiDefinition.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding && httpStatus >= http.StatusBadRequest {
				err = e.gqlTools.returnErrorsFromUpstream(proxyOnlyCtx, &resultWriter, e.seekReadCloser)
				if err != nil {
					return
				}
			}

		}
	}
	res = resultWriter.AsHTTPResponse(httpStatus, header)
	return
}

// selectContentEncodingToBeUsed selects the encoding value to be returned based on the IETF standards
// if acceptedEncoding is a list of comma separated strings br,gzip, deflate; then it selects the first supported one
// if it is a single value then it returns that value
// if no supported encoding is found, it returns the last value
func selectContentEncodingToBeUsed(acceptedEncoding string) string {
	supportedHeaders := map[string]struct{}{
		"gzip":    {},
		"deflate": {},
		"br":      {},
	}

	values := strings.Split(acceptedEncoding, ",")
	if len(values) < 2 {
		return values[0]
	}

	for i, e := range values {
		enc := strings.TrimSpace(e)
		if _, ok := supportedHeaders[enc]; ok {
			return enc
		}
		if i == len(values)-1 {
			return enc
		}
	}
	return ""
}

func (e *EngineV2) handoverWebSocketConnectionToGraphQLExecutionEngine(params *ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	conn, err := websocketConnWithUpgradeHeader(e.logger, params)
	if err != nil {
		e.logger.Error("could not upgrade websocket connection", abstractlogger.Error(err))
		return nil, false, err
	}

	done := make(chan bool)
	errChan := make(chan error)

	var executorPool subscription.ExecutorPool

	if e.ExecutionEngine == nil {
		e.logger.Error("could not start graphql websocket handler: execution engine is nil")
		return
	}
	initialRequestContext := subscription.NewInitialHttpRequestContext(params.OutRequest)
	upstreamHeaders := additionalUpstreamHeaders(e.logger, params.OutRequest, e.ApiDefinition)
	executorPool = subscription.NewExecutorV2Pool(
		e.ExecutionEngine,
		initialRequestContext,
		subscription.WithExecutorV2HeaderModifier(e.gqlTools.headerModifier(upstreamHeaders)),
	)

	go gqlwebsocket.Handle(
		done,
		errChan,
		conn,
		executorPool,
		gqlwebsocket.WithLogger(e.logger),
		gqlwebsocket.WithProtocolFromRequestHeaders(params.OutRequest),
	)
	select {
	case err := <-errChan:
		e.logger.Error("could not start graphql websocket handler: ", abstractlogger.Error(err))
	case <-done:
	}

	return nil, true, nil
}

// Interface Guard
var _ Engine = (*EngineV2)(nil)
