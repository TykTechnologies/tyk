package graphengine

import (
	"context"
	"errors"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/engine/datasource/httpclient"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/subscription"
	gqlwebsocketV2 "github.com/TykTechnologies/graphql-go-tools/v2/pkg/subscription/websocket"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/jensneuse/abstractlogger"
	"net/http"
)

func (e *EngineV3) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *EngineV3) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
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

	var executorPool subscription.ExecutorPool

	if e.engine == nil {
		e.logger.Error("could not start graphql websocket handler: execution engine is nil")
		return
	}
	initialRequestContext := subscription.NewInitialHttpRequestContext(params.OutRequest)
	upstreamHeaders := additionalUpstreamHeaders(e.logger, params.OutRequest, e.apiDefinitions)
	executorPool = subscription.NewExecutorV2Pool(
		e.engine,
		initialRequestContext,
		subscription.WithExecutorV2HeaderModifier(e.gqlTools.headerModifier(params.OutRequest, upstreamHeaders, e.tykVariableReplacer)),
	)

	go gqlwebsocketV2.Handle(
		done,
		errChan,
		conn,
		executorPool,
		gqlwebsocketV2.WithLogger(e.logger),
		gqlwebsocketV2.WithProtocolFromRequestHeaders(params.OutRequest),
	)
	select {
	case err := <-errChan:
		e.logger.Error("could not start graphql websocket handler: ", abstractlogger.Error(err))
	case <-done:
	}

	return nil, true, nil
}

func (e *EngineV3) handoverRequestToGraphQLExecutionEngine(gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	if e.engine == nil {
		err = errors.New("execution engine is nil")
		return
	}

	isProxyOnly := isProxyOnly(e.apiDefinitions)
	span := otel.SpanFromContext(outreq.Context())
	reqCtx := otel.ContextWithSpan(context.Background(), span)
	if isProxyOnly {
		reqCtx = SetProxyOnlyContextValue(reqCtx, outreq)
	}

	// TODO before fetch hook removed
	resultWriter := graphql.NewEngineResultWriter()
	execOptions := make([]graphql.ExecutionOptionsV2, 0)

	upstreamHeaders := additionalUpstreamHeaders(e.logger, outreq, e.apiDefinitions)
	execOptions = append(execOptions, graphql.WithHeaderModifier(e.gqlTools.headerModifier(outreq, upstreamHeaders, e.tykVariableReplacer)))

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
			contentEncoding := selectContentEncodingToBeUsed(proxyOnlyCtx.forwardedRequest.Header.Get(httpclient.AcceptEncodingHeader))
			header.Set(httpclient.ContentEncodingHeader, contentEncoding)
			if e.apiDefinitions.GraphQL.Proxy.UseResponseExtensions.OnErrorForwarding && httpStatus >= http.StatusBadRequest {
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
