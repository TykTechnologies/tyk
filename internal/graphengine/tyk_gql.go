package graphengine

import (
	"context"
	"errors"
	"github.com/TykTechnologies/tyk/apidef"
	"net/http"

	"github.com/TykTechnologies/tyk-gql/graphql"
	"github.com/jensneuse/abstractlogger"
)

type ContextRetrieveRequestFunc func(r *http.Request) *graphql.Request
type ContextStoreRequestFunc func(r *http.Request, gqlRequest *graphql.Request)

type tykGqlRequestProcessor struct {
	logger             abstractlogger.Logger
	schema             *graphql.Schema
	ctxRetrieveRequest ContextRetrieveRequestFunc
}

type reverseProxyPreHandler struct {
	ctxRetrieveGraphQLRequest ContextRetrieveRequestFunc
	apiDefinition             *apidef.APIDefinition
	httpClient                *http.Client
	newReusableBodyReadCloser NewReusableBodyReadCloserFunc
}

func (r *reverseProxyPreHandler) PreHandle(params ReverseProxyParams) (reverseProxyType ReverseProxyType, err error) {
	r.httpClient.Transport = NewGraphQLEngineTransport(
		DetermineGraphQLEngineTransportType(r.apiDefinition),
		params.RoundTripper,
		r.newReusableBodyReadCloser,
		params.HeadersConfig,
	)

	switch {
	case params.IsCORSPreflight:
		return ReverseProxyTypePreFlight, nil
	case params.IsWebSocketUpgrade:
		if params.NeedsEngine {
			return ReverseProxyTypeWebsocketUpgrade, nil
		}
	default:
		gqlRequest := r.ctxRetrieveGraphQLRequest(params.OutRequest)
		if gqlRequest == nil {
			err = errors.New("graphql request is nil")
			return
		}
		gqlRequest.SetHeader(params.OutRequest.Header)

		var isIntrospection bool
		isIntrospection, err = gqlRequest.IsIntrospectionQuery()
		if err != nil {
			return
		}

		if isIntrospection {
			return ReverseProxyTypeIntrospection, nil
		}
		if params.NeedsEngine {
			return ReverseProxyTypeGraphEngine, nil
		}
	}

	return ReverseProxyTypeNone, nil
}

func (t *tykGqlRequestProcessor) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
	if r == nil {
		t.logger.Error("request is nil")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	gqlRequest := t.ctxRetrieveRequest(r)

	normalizationResult, err := gqlRequest.Normalize(t.schema)
	if err != nil {
		t.logger.Error("error while normalizing GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return writeGraphQLError(t.logger, w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(t.schema)
	if err != nil {
		t.logger.Error("error while validating GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return writeGraphQLError(t.logger, w, validationResult.Errors)
	}

	inputValidationResult, err := gqlRequest.ValidateInput(t.schema)
	if err != nil {
		t.logger.Error("error while validating variables for request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	if inputValidationResult.Errors != nil && inputValidationResult.Errors.Count() > 0 {
		return writeGraphQLError(t.logger, w, inputValidationResult.Errors)
	}
	return nil, http.StatusOK
}

var _ GraphQLRequestProcessor = (*tykGqlRequestProcessor)(nil)
