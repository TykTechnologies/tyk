package gateway

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

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

	complexityCheck := &GraphqlComplexityChecker{logger: m.Logger()}
	failReason := complexityCheck.DepthLimitExceeded(gqlRequest, accessDef, m.Spec.GraphQLExecutor.Schema)
	return m.handleComplexityFailReason(failReason)
}

func (m *GraphQLComplexityMiddleware) handleComplexityFailReason(failReason ComplexityFailReason) (error, int) {
	switch failReason {
	case ComplexityFailReasonInternalError:
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	case ComplexityFailReasonDepthLimitExceeded:
		return GraphQLDepthLimitExceededErr, http.StatusForbidden
	}

	return nil, http.StatusOK
}

type GraphqlComplexityChecker struct {
	logger *logrus.Entry
}

func (c *GraphqlComplexityChecker) DepthLimitEnabled(accessDef *user.AccessDefinition) bool {
	// There is a possibility that depth limit is disabled on field level too,
	// but we could not determine this without analyzing actual requested fields.
	if len(accessDef.FieldAccessRights) > 0 {
		return true
	}

	// If MaxQueryDepth is -1 or 0, it means unlimited and no need for depth limiting.
	return accessDef.Limit.MaxQueryDepth > 0
}

func (c *GraphqlComplexityChecker) DepthLimitExceeded(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) ComplexityFailReason {
	if !c.DepthLimitEnabled(accessDef) {
		return ComplexityFailReasonNone
	}

	isIntrospectionQuery, err := gqlRequest.IsIntrospectionQuery()
	if err != nil {
		c.logger.Debugf("Error while checking for introspection query: '%s'", err.Error())
		return ComplexityFailReasonInternalError
	}

	if isIntrospectionQuery {
		return ComplexityFailReasonNone
	}

	complexityRes, err := gqlRequest.CalculateComplexity(graphql.DefaultComplexityCalculator, schema)
	if err != nil {
		c.logger.Errorf("Error while calculating complexity of GraphQL request: '%s'", err)
		return ComplexityFailReasonInternalError
	}

	if complexityRes.Errors != nil && complexityRes.Errors.Count() > 0 {
		c.logger.Errorf("Error while calculating complexity of GraphQL request: '%s'", complexityRes.Errors.ErrorByIndex(0))
		return ComplexityFailReasonInternalError
	}

	// do per query depth check
	if len(accessDef.FieldAccessRights) == 0 {
		if complexityRes.Depth > accessDef.Limit.MaxQueryDepth {
			c.logger.Debugf("Complexity of the request is higher than the allowed limit '%d'", accessDef.Limit.MaxQueryDepth)
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
				c.logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed field limit '%d'",
					fieldComplexityRes.Depth, fieldAccessDefinition.TypeName, fieldAccessDefinition.FieldName, fieldAccessDefinition.Limits.MaxQueryDepth)

				return ComplexityFailReasonDepthLimitExceeded
			}
			continue
		}

		// favour global limit for query field
		// have to increase resulting field depth by 1 to get a global depth
		queryDepth := fieldComplexityRes.Depth + 1
		if greaterThanInt(queryDepth, accessDef.Limit.MaxQueryDepth) {
			c.logger.Debugf("Depth '%d' of the root field: %s.%s is higher than the allowed global limit '%d'",
				queryDepth, fieldComplexityRes.TypeName, fieldComplexityRes.FieldName, accessDef.Limit.MaxQueryDepth)

			return ComplexityFailReasonDepthLimitExceeded
		}
	}
	return ComplexityFailReasonNone
}
