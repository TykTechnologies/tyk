package graphengine

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/subscription"
	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/otel"
)

type EngineV1 struct {
	ExecutionEngine    *graphql.ExecutionEngine
	Schema             *graphql.Schema
	ApiDefinition      *apidef.APIDefinition
	HttpClient         *http.Client
	OTelConfig         otel.OpenTelemetry
	OTelTracerProvider otel.TracerProvider

	logger                  abstractlogger.Logger
	gqlTools                graphqlGoToolsV1
	graphqlRequestProcessor GraphQLRequestProcessor
	complexityChecker       ComplexityChecker
	granularAccessChecker   GranularAccessChecker
	reverseProxyPreHandler  ReverseProxyPreHandler
	ctxStoreRequestFunc     func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc  func(r *http.Request) *graphql.Request
	engineTransportModifier TransportModifier
}

type EngineV1Options struct {
	Logger                  *logrus.Logger
	ApiDefinition           *apidef.APIDefinition
	HttpClient              *http.Client
	OTelConfig              otel.OpenTelemetry
	OTelTracerProvider      otel.TracerProvider
	PreSendHttpHook         datasource.PreSendHttpHook
	PostReceiveHttpHook     datasource.PostReceiveHttpHook
	ContextStoreRequest     ContextStoreRequestV1Func
	ContextRetrieveRequest  ContextRetrieveRequestV1Func
	EngineTransportModifier TransportModifier
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

	reverseProxyPreHandler := &reverseProxyPreHandlerV1{
		ctxRetrieveGraphQLRequest: options.ContextRetrieveRequest,
		apiDefinition:             options.ApiDefinition,
		httpClient:                options.HttpClient,
		transportModifier:         options.EngineTransportModifier,
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
		reverseProxyPreHandler:  reverseProxyPreHandler,
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

func (e *EngineV1) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	reverseProxyType, err := e.reverseProxyPreHandler.PreHandle(params)
	if err != nil {
		e.logger.Error("error on reverse proxy pre handler", abstractlogger.Error(err))
		return nil, false, err
	}

	gqlRequest := e.ctxRetrieveRequestFunc(params.OutRequest)

	switch reverseProxyType {
	case ReverseProxyTypeIntrospection:
		return e.handleGraphQLIntrospection()
	case ReverseProxyTypeWebsocketUpgrade:
		break
	case ReverseProxyTypeGraphEngine:
		return e.handoverRequestToGraphQLExecutionEngine(params.RoundTripper, gqlRequest, params.OutRequest)
	default:
		e.logger.Error("unknown reverse proxy type", abstractlogger.Int("reverseProxyType", int(reverseProxyType)))
	}

	return nil, false, nil
}

func (e *EngineV1) handleGraphQLIntrospection() (res *http.Response, hijacked bool, err error) {
	var result *graphql.ExecutionResult
	result, err = graphql.SchemaIntrospection(e.Schema)
	if err != nil {
		return
	}

	res = result.GetAsHTTPResponse()
	return
}

func (e *EngineV1) handoverRequestToGraphQLExecutionEngine(roundTripper http.RoundTripper, gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	//p.TykAPISpec.GraphQLExecutor.Client.Transport = NewGraphQLEngineTransport(DetermineGraphQLEngineTransportType(p.TykAPISpec), roundTripper)

	if e.ExecutionEngine == nil {
		err = errors.New("execution engine is nil")
		return
	}

	var result *graphql.ExecutionResult
	result, err = e.ExecutionEngine.Execute(context.Background(), gqlRequest, graphql.ExecutionOptions{ExtraArguments: gqlRequest.Variables})
	if err != nil {
		return
	}

	res = result.GetAsHTTPResponse()
	return
}

func (e *EngineV1) handleWebsocketUpgrade(params *ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	conn, err := params.WebSocketUpgrader.Upgrade(params.ResponseWriter, params.OutRequest, http.Header{
		header.SecWebSocketProtocol: {params.OutRequest.Header.Get(header.SecWebSocketProtocol)},
	})
	if err != nil {
		e.logger.Error("websocket upgrade for GraphQL engine failed", abstractlogger.Error(err))
		return nil, false, err
	}

	e.handoverWebSocketConnectionToGraphQLExecutionEngine(params.RoundTripper, conn.UnderlyingConn(), params.OutRequest)
	return nil, true, nil
}

func (e *EngineV1) handoverWebSocketConnectionToGraphQLExecutionEngine(roundTripper http.RoundTripper, conn net.Conn, req *http.Request) {
	done := make(chan bool)
	errChan := make(chan error)

	var executorPool subscription.ExecutorPool
	if e.ExecutionEngine == nil {
		e.logger.Error("could not start graphql websocket handler: execution engine is nil")
		return
	}
	executorPool = subscription.NewExecutorV1Pool(e.ExecutionEngine.NewExecutionHandler())

	go gqlwebsocket.Handle(
		done,
		errChan,
		conn,
		executorPool,
		gqlwebsocket.WithLogger(e.logger),
		gqlwebsocket.WithProtocolFromRequestHeaders(req),
	)
	select {
	case err := <-errChan:
		e.logger.Error("could not start graphql websocket handler: ", abstractlogger.Error(err))
	case <-done:
	}
}

// Interface Guard
var _ Engine = (*EngineV1)(nil)
