package gateway

import (
	"errors"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/user"
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
	accessDef, _, err := GetAccessDefinitionByAPIIDOrSession(ctxGetSession(r), m.Spec)
	if err != nil {
		m.Logger().Debugf("Error while calculating GraphQL complexity: '%s'", err)
		return m.handleComplexityFailReason(ComplexityFailReasonInternalError)
	}

	gqlRequest := ctxGetGraphQLRequest(r)
	if gqlRequest == nil {
		return nil, http.StatusOK
	}

	// If MaxQueryDepth is -1 or 0, it means unlimited and no need for depth limiting.
	if m.DepthLimitEnabled(accessDef) {
		if failReason := m.DepthLimitExceeded(gqlRequest, accessDef, m.Spec.GraphQLExecutor.Schema); failReason != ComplexityFailReasonNone {
			return m.handleComplexityFailReason(failReason)
		}
	}

	return nil, http.StatusOK
}

func (m *GraphQLComplexityMiddleware) DepthLimitEnabled(accessDef *user.AccessDefinition) bool {
	// There is a possibility that depth limit is disabled on field level too,
	// but we could not determine this without analyzing actual requested fields.
	if len(accessDef.FieldAccessRights) > 0 {
		return true
	}

	return accessDef.Limit.MaxQueryDepth > 0
}

func (m *GraphQLComplexityMiddleware) DepthLimitExceeded(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) ComplexityFailReason {
	complexityRes, err := gqlRequest.CalculateComplexity(graphql.DefaultComplexityCalculator, schema)
	if err != nil {
		log.Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		return ComplexityFailReasonInternalError
	}

	// do per query depth check
	if len(accessDef.FieldAccessRights) == 0 {
		if complexityRes.Depth > accessDef.Limit.MaxQueryDepth {
			log.Debugf("Complexity of the request is higher than the allowed limit '%d'", accessDef.Limit.MaxQueryDepth)
			return ComplexityFailReasonDepthLimitExceeded
		}
		return ComplexityFailReasonNone
	}

	// do per query field depth check
	for _, fieldComplexityRes := range complexityRes.PerRootField {
		var (
			fieldAccessDefinition user.FieldAccessDefinition
			hasPerFieldLimits     bool
		)

		for _, fieldAccessRight := range accessDef.FieldAccessRights {
			if fieldComplexityRes.TypeName != fieldAccessRight.TypeName {
				continue
			}
			if fieldComplexityRes.FieldName != fieldAccessRight.FieldName {
				continue
			}

			fieldAccessDefinition = fieldAccessRight
			hasPerFieldLimits = true
			break
		}

		if hasPerFieldLimits {
			if greaterThanInt(fieldComplexityRes.Depth, fieldAccessDefinition.Limits.MaxQueryDepth) {
				log.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed field limit '%d'",
					fieldComplexityRes.Depth, fieldAccessDefinition.TypeName, fieldAccessDefinition.FieldName, fieldAccessDefinition.Limits.MaxQueryDepth)

				return ComplexityFailReasonDepthLimitExceeded
			}
			continue
		}

		// favour global limit for query field
		// have to increase resulting field depth by 1 to get a global depth
		queryDepth := fieldComplexityRes.Depth + 1
		if greaterThanInt(queryDepth, accessDef.Limit.MaxQueryDepth) {
			log.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed global limit '%d'",
				queryDepth, fieldComplexityRes.TypeName, fieldComplexityRes.FieldName, accessDef.Limit.MaxQueryDepth)

			return ComplexityFailReasonDepthLimitExceeded
		}
	}
	return ComplexityFailReasonNone
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
