//go:build v52
// +build v52

package gateway

import (
	"context"
	"errors"
	"net/http"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/internal/graphql"
)

func (m *GraphQLMiddleware) setupOpenTelemetry() error {
	conf := m.Gw.GetConfig()
	engine := m.Spec.GraphQLExecutor.EngineV2
	if conf.OpenTelemetry.Enabled {
		executor, err := graphql.NewOtelGraphqlEngineV2(m.Gw.TracerProvider, engine)
		if err != nil {
			return err
		}
		m.Spec.GraphQLExecutor.OtelExecutor = executor
	}
	return nil
}

func (m *GraphQLMiddleware) process(w http.ResponseWriter, r *http.Request, gqlRequest *gql.Request) (error, int) {
	if conf := m.Gw.GetConfig(); conf.OpenTelemetry.Enabled {
		ctx, span := m.Gw.TracerProvider.Tracer().Start(r.Context(), "GraphqlMiddleware Validation")
		defer span.End()
		*r = *r.WithContext(ctx)
		return m.validateRequestWithOtel(r.Context(), w, gqlRequest)
	}
	return m.validateRequest(w, r, gqlRequest)
}

func (m *GraphQLMiddleware) validateRequestWithOtel(ctx context.Context, w http.ResponseWriter, req *gql.Request) (error, int) {
	m.Spec.GraphQLExecutor.OtelExecutor.SetContext(ctx)

	// normalization
	err := m.Spec.GraphQLExecutor.OtelExecutor.Normalize(req)
	if err != nil {
		m.Logger().Errorf("Error while normalizing GraphqlRequest: %v", err)
		var reqErr gql.RequestErrors
		if errors.As(err, &reqErr) {
			return m.writeGraphQLError(w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// validation
	err = m.Spec.GraphQLExecutor.OtelExecutor.ValidateForSchema(req)
	if err != nil {
		m.Logger().Errorf("Error while validating GraphQL request: '%s'", err)
		var reqErr gql.RequestErrors
		if errors.As(err, &reqErr) {
			return m.writeGraphQLError(w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}

	// input validation
	err = m.Spec.GraphQLExecutor.OtelExecutor.InputValidation(req)
	if err != nil {
		m.Logger().Errorf("Error while validating variables for request: %v", err)
		var reqErr gql.RequestErrors
		if errors.As(err, &reqErr) {
			return m.writeGraphQLError(w, reqErr)
		}
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	}
	return nil, http.StatusOK
}
