package graphengine

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk-gql/graphql"
	"github.com/jensneuse/abstractlogger"
)

type ProxyOnlyContextRetrieveRequestFunc func(r *http.Request) *graphql.Request
type ProxyOnlyContextStoreRequestFunc func(r *http.Request, gqlRequest *graphql.Request)

type proxyOnlyRequestProcessor struct {
	logger             abstractlogger.Logger
	schema             *graphql.Schema
	ctxRetrieveRequest ProxyOnlyContextRetrieveRequestFunc
}

func (t *proxyOnlyRequestProcessor) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
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

var _ GraphQLRequestProcessor = (*proxyOnlyRequestProcessor)(nil)
