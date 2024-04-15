package graphengine

import (
	"context"
	"fmt"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/graphql"
	"github.com/jensneuse/abstractlogger"
	"net/http"
)

type ContextRetrieveRequestV2Func func(r *http.Request) *graphql.Request
type ContextStoreRequestV2Func func(r *http.Request, gqlRequest *graphql.Request)

type graphqlGoToolsV2 struct{}

func (g graphqlGoToolsV2) parseSchema(schema string) (*graphql.Schema, error) {
	parsed, err := graphql.NewSchemaFromString(schema)
	if err != nil {
		return nil, err
	}

	normalizeResult, err := parsed.Normalize()
	if err != nil {
		return nil, err
	}

	if !normalizeResult.Successful {
		return nil, fmt.Errorf("error normalizing schema: %w", normalizeResult.Errors)
	}

	return parsed, nil
}

type graphqlRequestProcessorV2 struct {
	logger             abstractlogger.Logger
	schema             *graphql.Schema
	ctxRetrieveRequest ContextRetrieveRequestV2Func
}

func (g *graphqlRequestProcessorV2) ProcessRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) (error, int) {
	if r == nil {
		g.logger.Error("request is nil")
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	v1Request := g.ctxRetrieveRequest(r)
	gqlRequest := graphql.Request{
		Variables:     v1Request.Variables,
		Query:         v1Request.Query,
		OperationName: v1Request.OperationName,
	}
	normalizationResult, err := gqlRequest.Normalize(g.schema)
	if err != nil {
		g.logger.Error("error while normalizing GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if normalizationResult.Errors != nil && normalizationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, normalizationResult.Errors)
	}

	validationResult, err := gqlRequest.ValidateForSchema(g.schema)
	if err != nil {
		g.logger.Error("error while validating GraphQL request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	if validationResult.Errors != nil && validationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, validationResult.Errors)
	}

	inputValidationResult, err := gqlRequest.ValidateInput(g.schema)
	if err != nil {
		g.logger.Error("error while validating variables for request", abstractlogger.Error(err))
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	if inputValidationResult.Errors != nil && inputValidationResult.Errors.Count() > 0 {
		return writeGraphQLError(g.logger, w, inputValidationResult.Errors)
	}
	return nil, http.StatusOK
}
