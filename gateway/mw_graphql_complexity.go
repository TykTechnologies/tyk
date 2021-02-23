package gateway

import (
	"errors"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
)

type ComplexityFailReason int

const (
	ComplexityFailReasonNone ComplexityFailReason = iota
	ComplexityFailReasonInternalError
	ComplexityFailReasonDepthLimitExceeded
)

type GraphQLComplexityMiddleware struct {
	BaseMiddleware
}

func (m *GraphQLComplexityMiddleware) Name() string {
	return "GraphQLComplexityMiddleware"
}

func (m *GraphQLComplexityMiddleware) EnabledForSpec() bool {
	return m.Spec.GraphQL.Enabled
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *GraphQLComplexityMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	accessDef, _, err := GetAccessDefinitionByAPIIDOrSession(ctxGetSession(r), m.Spec.APIID)
	if err != nil {
		m.Logger().Debugf("Error while calculating GraphQL complexity: '%s'", err)
		return m.handleComplexityFailReason(ComplexityFailReasonInternalError)
	}

	gqlRequest := ctxGetGraphQLRequest(r)

	if accessDef.Limit.MaxQueryDepth <= 0 {
		return nil, http.StatusOK
	}

	complexityRes, err := gqlRequest.CalculateComplexity(graphql.DefaultComplexityCalculator, m.Spec.GraphQLExecutor.Schema)
	if err != nil {
		m.Logger().Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		return m.handleComplexityFailReason(ComplexityFailReasonInternalError)
	}

	if complexityRes.Depth > accessDef.Limit.MaxQueryDepth {
		m.Logger().Debugf("Complexity of the request is higher than the allowed limit '%d'", accessDef.Limit.MaxQueryDepth)
		return m.handleComplexityFailReason(ComplexityFailReasonDepthLimitExceeded)
	}

	return nil, http.StatusOK
}

func (m *GraphQLComplexityMiddleware) handleComplexityFailReason(failReason ComplexityFailReason) (error, int) {
	switch failReason {
	case ComplexityFailReasonInternalError:
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	case ComplexityFailReasonDepthLimitExceeded:
		return errors.New("depth limit exceeded"), http.StatusForbidden
	}

	return nil, http.StatusOK
}
