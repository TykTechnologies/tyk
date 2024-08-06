package graphengine

import (
	"context"
	"io"
	"net/http"

	"github.com/TykTechnologies/tyk-gql/graphql"
	"github.com/TykTechnologies/tyk-gql/httpclient"
	"github.com/TykTechnologies/tyk/apidef"
	graphqlinternal "github.com/TykTechnologies/tyk/internal/graphql"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/buger/jsonparser"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
)

type ProxyOnlyEngineOTelConfig struct {
	Enabled        bool
	Config         otel.OpenTelemetry
	TracerProvider otel.TracerProvider
	Executor       graphqlinternal.TykOtelExecutorI
}

type ProxyOnlyEngineInjections struct {
	ContextStoreRequest       ContextStoreRequestFunc
	ContextRetrieveRequest    ContextRetrieveRequestFunc
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
	TykVariableReplacer       TykVariableReplacer
}

type ProxyOnlyEngineOptions struct {
	Logger          *logrus.Logger
	Schema          *graphql.Schema
	ApiDefinition   *apidef.APIDefinition
	HttpClient      *http.Client
	StreamingClient *http.Client
	OpenTelemetry   ProxyOnlyEngineOTelConfig
	Injections      ProxyOnlyEngineInjections
}

// ProxyOnlyEngine implements Engine interface and only supports a proxy-only mode.
type ProxyOnlyEngine struct {
	Schema                    *graphql.Schema
	logger                    abstractlogger.Logger
	ApiDefinition             *apidef.APIDefinition
	OpenTelemetry             *ProxyOnlyEngineOTelConfig
	graphqlRequestProcessor   GraphQLRequestProcessor
	reverseProxyPreHandler    ReverseProxyPreHandler
	httpClient                *http.Client
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	seekReadCloser            SeekReadCloserFunc
	context                   context.Context
	contextCancel             context.CancelFunc
}

func NewProxyOnlyEngine(options ProxyOnlyEngineOptions) *ProxyOnlyEngine {
	logger := createAbstractLogrusLogger(options.Logger)
	ctx, cancel := context.WithCancel(context.Background())

	requestProcessor := &tykGqlRequestProcessor{
		logger:             logger,
		schema:             options.Schema,
		ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	}

	reverseProxyPreHdlr := &reverseProxyPreHandlerV4{
		ctxRetrieveGraphQLRequest: options.Injections.ContextRetrieveRequest,
		apiDefinition:             options.ApiDefinition,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
	}

	return &ProxyOnlyEngine{
		context:                   ctx,
		contextCancel:             cancel,
		Schema:                    options.Schema,
		logger:                    logger,
		httpClient:                options.HttpClient,
		ApiDefinition:             options.ApiDefinition,
		OpenTelemetry:             &options.OpenTelemetry,
		graphqlRequestProcessor:   requestProcessor,
		reverseProxyPreHandler:    reverseProxyPreHdlr,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
		seekReadCloser:            options.Injections.SeekReadCloser,
		ctxStoreRequestFunc:       options.Injections.ContextStoreRequest,
		ctxRetrieveRequestFunc:    options.Injections.ContextRetrieveRequest,
	}
}

func (e *ProxyOnlyEngine) Version() EngineVersion {
	return EngineVersionV4
}

func (e *ProxyOnlyEngine) HasSchema() bool {
	return e.Schema != nil
}

func (e *ProxyOnlyEngine) Cancel() {
	if e.contextCancel != nil {
		e.contextCancel()
	}
}

func (e *ProxyOnlyEngine) ProcessAndStoreGraphQLRequest(w http.ResponseWriter, r *http.Request) (err error, statusCode int) {
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

func (e *ProxyOnlyEngine) ProcessGraphQLComplexity(r *http.Request, accessDefinition *ComplexityAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *ProxyOnlyEngine) ProcessGraphQLGranularAccess(w http.ResponseWriter, r *http.Request, accessDefinition *GranularAccessDefinition) (err error, statusCode int) {
	//TODO implement me
	panic("implement me")
}

func (e *ProxyOnlyEngine) HandleReverseProxy(params ReverseProxyParams) (res *http.Response, hijacked bool, err error) {
	e.httpClient.Transport = NewGraphQLEngineTransport(
		DetermineGraphQLEngineTransportType(e.ApiDefinition),
		params.RoundTripper,
		e.newReusableBodyReadCloser,
		params.HeadersConfig,
	)

	reverseProxyType, err := e.reverseProxyPreHandler.PreHandle(params)
	if err != nil {
		e.logger.Error("error on reverse proxy pre handler", abstractlogger.Error(err))
		return nil, false, err
	}

	//gqlRequest := e.ctxRetrieveRequestFunc(params.OutRequest)

	// TODO: Bring back the Cleanup method
	switch reverseProxyType {
	//case ReverseProxyTypeIntrospection:
	//	return e.gqlTools.handleIntrospection(e.Schema)
	//case ReverseProxyTypeWebsocketUpgrade:
	//	return e.handoverWebSocketConnectionToGraphQLExecutionEngine(&params)
	case ReverseProxyTypeGraphEngine:
		//return e.handoverRequestToGraphQLExecutionEngine(gqlRequest, params.OutRequest)
	//case ReverseProxyTypePreFlight:
	//	if e.ApiDefinition.GraphQL.ExecutionMode == apidef.GraphQLExecutionModeProxyOnly {
	//		return nil, false, nil
	//	}
	//	return nil, false, errors.New("options passthrough not allowed")
	case ReverseProxyTypeNone:
		return nil, false, nil
	}

	e.logger.Error("unknown reverse proxy type", abstractlogger.Int("reverseProxyType", int(reverseProxyType)))
	return nil, false, ErrUnknownReverseProxyType
}

func (e *ProxyOnlyEngine) handoverRequestToGraphQLExecutionEngine(gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	isProxyOnly := isProxyOnly(e.ApiDefinition)
	span := otel.SpanFromContext(outreq.Context())
	reqCtx := otel.ContextWithSpan(context.Background(), span)
	if isProxyOnly {
		reqCtx = SetProxyOnlyContextValue(reqCtx, outreq)
	}

	httpStatus := http.StatusOK
	header := make(http.Header)
	header.Set("Content-Type", "application/json")

	resultWriter := graphql.NewEngineResultWriter()

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
			err = e.returnErrorsFromUpstream(proxyOnlyCtx, &resultWriter, e.seekReadCloser)
			if err != nil {
				return
			}
		}
	}

	res = resultWriter.AsHTTPResponse(httpStatus, header)
	return
}

func (e *ProxyOnlyEngine) returnErrorsFromUpstream(proxyOnlyCtx *GraphQLProxyOnlyContextValues, resultWriter *graphql.EngineResultWriter, seekReadCloser SeekReadCloserFunc) error {
	body, err := seekReadCloser(proxyOnlyCtx.upstreamResponse.Body)
	if body == nil {
		// Response body already read by graphql-go-tools, and it's not re-readable. Quit silently.
		return nil
	} else if err != nil {
		return err
	}

	responseBody, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	// graphql-go-tools error message format: {"errors": [...]}
	// Insert the upstream error into the first error message.
	result, err := jsonparser.Set(resultWriter.Bytes(), responseBody, "errors", "[0]", "extensions")
	if err != nil {
		return err
	}
	resultWriter.Reset()
	_, err = resultWriter.Write(result)
	return err
}

// Interface Guard
var _ Engine = (*ProxyOnlyEngine)(nil)
