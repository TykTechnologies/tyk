package graphengine

import (
	"context"
	"errors"
	"net/http"

	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/execution/datasource"
	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/pkg/subscription"
	gqlwebsocket "github.com/TykTechnologies/graphql-go-tools/pkg/subscription/websocket"

	"github.com/TykTechnologies/tyk/apidef"
)

type EngineV1Injections struct {
	PreSendHttpHook           datasource.PreSendHttpHook
	PostReceiveHttpHook       datasource.PostReceiveHttpHook
	ContextStoreRequest       ContextStoreRequestV1Func
	ContextRetrieveRequest    ContextRetrieveRequestV1Func
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

type EngineV1 struct {
	ExecutionEngine *graphql.ExecutionEngine
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client

	logger                    abstractlogger.Logger
	gqlTools                  graphqlGoToolsV1
	graphqlRequestProcessor   GraphQLRequestProcessor
	complexityChecker         ComplexityChecker
	granularAccessChecker     GranularAccessChecker
	reverseProxyPreHandler    ReverseProxyPreHandler
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

type EngineV1Options struct {
	Logger        *logrus.Logger
	ApiDefinition *apidef.APIDefinition
	Schema        *graphql.Schema
	HttpClient    *http.Client
	Injections    EngineV1Injections
}

func NewEngineV1(options EngineV1Options) (*EngineV1, error) {
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

	executionEngine, err := gqlTools.createExecutionEngine(createExecutionEngineV1Params{
		logger:              logger,
		apiDef:              options.ApiDefinition,
		schema:              parsedSchema,
		httpClient:          options.HttpClient,
		preSendHttpHook:     options.Injections.PreSendHttpHook,
		postReceiveHttpHook: options.Injections.PostReceiveHttpHook,
	})
	if err != nil {
		logger.Error("error on execution engine creation", abstractlogger.Error(err))
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

	return &EngineV1{
		ExecutionEngine:         executionEngine,
		Schema:                  parsedSchema,
		ApiDefinition:           options.ApiDefinition,
		HttpClient:              options.HttpClient,
		logger:                  logger,
		gqlTools:                gqlTools,
		graphqlRequestProcessor: requestProcessor,
		complexityChecker:       complexityChecker,
		granularAccessChecker:   granularAccessChecker,
		reverseProxyPreHandler:  reverseProxyPreHandler,
		ctxStoreRequestFunc:     options.Injections.ContextStoreRequest,
		ctxRetrieveRequestFunc:  options.Injections.ContextRetrieveRequest,
	}, nil
}

func (e *EngineV1) Version() EngineVersion {
	return EngineVersionV1
}

func (e *EngineV1) HasSchema() bool {
	return e.Schema != nil
}

func (e *EngineV1) Cancel() {
	// V1 does not have a cancel callback
}

func (e *EngineV1) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
	var gqlRequest graphql.Request
	err = graphql.UnmarshalRequest(r.Body, &gqlRequest)
	if err != nil {
		e.logger.Debug("error while unmarshalling GraphQL request", abstractlogger.Error(err))
		return err, http.StatusBadRequest
	}

	e.ctxStoreRequestFunc(r, &gqlRequest)
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
		return e.gqlTools.handleIntrospection(e.Schema)
	case ReverseProxyTypeWebsocketUpgrade:
		return e.handoverWebSocketConnectionToGraphQLExecutionEngine(&params)
	case ReverseProxyTypeGraphEngine:
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

func (e *EngineV1) handoverRequestToGraphQLExecutionEngine(gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
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

func (e *EngineV1) handoverWebSocketConnectionToGraphQLExecutionEngine(params *ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
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
	executorPool = subscription.NewExecutorV1Pool(e.ExecutionEngine.NewExecutionHandler())

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
var _ Engine = (*EngineV1)(nil)
