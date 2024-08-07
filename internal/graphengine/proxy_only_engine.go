package graphengine

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/TykTechnologies/tyk-gql/graphql"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/jensneuse/abstractlogger"
	"github.com/sirupsen/logrus"
)

type ProxyOnlyEngineInjections struct {
	ContextStoreRequest       ProxyOnlyContextStoreRequestFunc
	ContextRetrieveRequest    ProxyOnlyContextRetrieveRequestFunc
	NewReusableBodyReadCloser NewReusableBodyReadCloserFunc
	SeekReadCloser            SeekReadCloserFunc
}

type ProxyOnlyEngineOptions struct {
	Logger        *logrus.Logger
	Schema        *graphql.Schema
	ApiDefinition *apidef.APIDefinition
	TLSConfig     *tls.Config
	Injections    ProxyOnlyEngineInjections
}

// ProxyOnlyEngine implements Engine interface and only supports a proxy-only mode.
type ProxyOnlyEngine struct {
	Schema                    *graphql.Schema
	logger                    abstractlogger.Logger
	ApiDefinition             *apidef.APIDefinition
	graphqlRequestProcessor   GraphQLRequestProcessor
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
	tlsConfig                 *tls.Config
	ctxStoreRequestFunc       func(r *http.Request, gqlRequest *graphql.Request)
	ctxRetrieveRequestFunc    func(r *http.Request) *graphql.Request
	seekReadCloser            SeekReadCloserFunc
	context                   context.Context
	contextCancel             context.CancelFunc
}

func NewProxyOnlyEngine(options ProxyOnlyEngineOptions) *ProxyOnlyEngine {
	logger := createAbstractLogrusLogger(options.Logger)
	ctx, cancel := context.WithCancel(context.Background())

	requestProcessor := &proxyOnlyRequestProcessor{
		logger:             logger,
		schema:             options.Schema,
		ctxRetrieveRequest: options.Injections.ContextRetrieveRequest,
	}

	return &ProxyOnlyEngine{
		context:                   ctx,
		contextCancel:             cancel,
		Schema:                    options.Schema,
		logger:                    logger,
		ApiDefinition:             options.ApiDefinition,
		graphqlRequestProcessor:   requestProcessor,
		tlsConfig:                 options.TLSConfig,
		newReusableBodyReadCloser: options.Injections.NewReusableBodyReadCloser,
		seekReadCloser:            options.Injections.SeekReadCloser,
		ctxStoreRequestFunc:       options.Injections.ContextStoreRequest,
		ctxRetrieveRequestFunc:    options.Injections.ContextRetrieveRequest,
	}
}

func (e *ProxyOnlyEngine) Version() EngineVersion {
	return EngineVersionProxyOnly
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
	roundTripper := NewGraphQLEngineTransport(
		GraphQLEngineTransportTypeProxyOnly,
		params.RoundTripper,
		e.newReusableBodyReadCloser,
		params.HeadersConfig,
	)
	res, err = roundTripper.RoundTrip(params.OutRequest)
	if err != nil {
		return nil, false, err
	}
	return res, false, nil
}

// Interface Guard
var _ Engine = (*ProxyOnlyEngine)(nil)
