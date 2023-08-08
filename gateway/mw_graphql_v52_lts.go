//go:build !v52
// +build !v52

package gateway

import (
	"net/http"

	gql "github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
)

func (m *GraphQLMiddleware) setupOpenTelemetry() error {
	return nil
}

func (m *GraphQLMiddleware) process(w http.ResponseWriter, r *http.Request, gqlRequest *gql.Request) (error, int) {
	return m.validateRequest(w, r, gqlRequest)
}
