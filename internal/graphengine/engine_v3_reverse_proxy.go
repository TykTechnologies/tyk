package graphengine

import (
	"context"
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/jensneuse/abstractlogger"

	httpclientv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/httpclient"
	graphqlv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	subscriptionv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/subscription"
	gqlwebsocketv2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/subscription/websocket"
	"github.com/TykTechnologies/tyk/internal/otel"
)

func (e *EngineV3) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	return complexityFailReasonAsHttpStatusCode(e.complexityChecker.DepthLimitExceeded(r, accessDefinition))
}

func (e *EngineV3) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	result := e.granularAccessChecker.CheckGraphQLRequestFieldAllowance(w, r, accessDefinition)
	return granularAccessFailReasonAsHttpStatusCode(e.logger, &result, w)
}

func (e *EngineV3) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	reverseProxyType, err := e.reverseProxyPreHandler.PreHandle(params)
	if err != nil {
		e.logger.Error("error on reverse proxy pre handler", abstractlogger.Error(err))
		return nil, false, err
	}

	gqlRequest := e.ctxRetrieveRequestFunc(params.OutRequest)
	switch reverseProxyType {
	case ReverseProxyTypeIntrospection:
		return e.gqlTools.handleIntrospection(e.schema)
	case ReverseProxyTypeWebsocketUpgrade:
		return e.handoverWebSocketConnectionToGraphQLExecutionEngine(&params)
	case ReverseProxyTypeGraphEngine:
		return e.handoverRequestToGraphQLExecutionEngine(gqlRequest, params.OutRequest)
	case ReverseProxyTypePreFlight:
		if e.apiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly {
			return nil, false, nil
		}
		return nil, false, errors.New("options passthrough not allowed")
	case ReverseProxyTypeNone:
		return nil, false, nil
	}

	e.logger.Error("unknown reverse proxy type", abstractlogger.Int("reverseProxyType", int(reverseProxyType)))
	return nil, false, ErrUnknownReverseProxyType
}

func (e *EngineV3) handoverWebSocketConnectionToGraphQLExecutionEngine(params *ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	conn, err := websocketConnWithUpgradeHeader(e.logger, params)
	if err != nil {
		e.logger.Error("could not upgrade websocket connection", abstractlogger.Error(err))
		return nil, false, err
	}

	done := make(chan bool)
	errChan := make(chan error)

	var executorPool subscriptionv2.ExecutorPool

	if e.engine == nil {
		e.logger.Error("could not start graphql websocket handler: execution engine is nil")
		return
	}
	initialRequestContext := subscriptionv2.NewInitialHttpRequestContext(params.OutRequest)
	upstreamHeaders := additionalUpstreamHeaders(e.logger, params.OutRequest, e.apiDefinition)
	executorPool = subscriptionv2.NewExecutorV2Pool(
		e.engine,
		initialRequestContext,
		subscriptionv2.WithExecutorV2HeaderModifier(e.gqlTools.headerModifier(params.OutRequest, upstreamHeaders, e.tykVariableReplacer)),
	)

	go gqlwebsocketv2.Handle(
		done,
		errChan,
		conn,
		executorPool,
		gqlwebsocketv2.WithLogger(e.logger),
		gqlwebsocketv2.WithProtocolFromRequestHeaders(params.OutRequest),
	)
	select {
	case err := <-errChan:
		e.logger.Error("could not start graphql websocket handler: ", abstractlogger.Error(err))
	case <-done:
	}

	return nil, true, nil
}

func (e *EngineV3) handoverRequestToGraphQLExecutionEngine(gqlRequest *graphqlv2.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	if e.engine == nil {
		err = errors.New("execution engine is nil")
		return
	}

	isProxyOnly := isProxyOnly(e.apiDefinition)
	span := otel.SpanFromContext(outreq.Context())
	reqCtx := otel.ContextWithSpan(context.Background(), span)
	if isProxyOnly {
		reqCtx = SetProxyOnlyContextValue(reqCtx, outreq)
	}

	// TODO before fetch hook removed
	resultWriter := graphqlv2.NewEngineResultWriter()
	execOptions := make([]graphqlv2.ExecutionOptionsV2, 0)

	upstreamHeaders := additionalUpstreamHeaders(e.logger, outreq, e.apiDefinition)
	execOptions = append(execOptions, graphqlv2.WithHeaderModifier(e.gqlTools.headerModifier(outreq, upstreamHeaders, e.tykVariableReplacer)))

	if e.openTelemetry.Executor != nil {
		//if err = e.openTelemetry.Executor.Execute(reqCtx, gqlRequest, &resultWriter, execOptions...); err != nil {
		//	return
		//}
	} else {
		err = e.engine.Execute(reqCtx, gqlRequest, &resultWriter, execOptions...)
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
			contentEncoding := selectContentEncodingToBeUsed(proxyOnlyCtx.forwardedRequest.Header.Get(httpclientv2.AcceptEncodingHeader))
			header.Set(httpclientv2.ContentEncodingHeader, contentEncoding)
			if e.apiDefinition.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding && httpStatus >= http.StatusBadRequest {
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
