package gateway

import (
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/internal/graphengine"
	"github.com/TykTechnologies/tyk/user"
)

type GranularAccessFailReason int

const (
	GranularAccessFailReasonNone GranularAccessFailReason = iota
	GranularAccessFailReasonInternalError
	GranularAccessFailReasonValidationError
)

const RestrictedFieldValidationFailedLogMsg = "Error during GraphQL request restricted fields validation: '%s'"

type GraphQLGranularAccessMiddleware struct {
	*BaseMiddleware
}

func (m *GraphQLGranularAccessMiddleware) Name() string {
	return "GraphQLGranularAccessMiddleware"
}

func (m *GraphQLGranularAccessMiddleware) EnabledForSpec() bool {
	return m.Spec.GraphQL.Enabled
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *GraphQLGranularAccessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	session := ctxGetSession(r)

	accessDef, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	graphEngineGranularAccessDefinition := &graphengine.GranularAccessDefinition{
		AllowedTypes:         make([]graphengine.GranularAccessType, 0),
		RestrictedTypes:      make([]graphengine.GranularAccessType, 0),
		DisableIntrospection: accessDef.DisableIntrospection,
	}

	for _, allowedType := range accessDef.AllowedTypes {
		graphEngineGranularAccessDefinition.AllowedTypes = append(graphEngineGranularAccessDefinition.AllowedTypes, graphengine.GranularAccessType{
			Name:   allowedType.Name,
			Fields: allowedType.Fields,
		})
	}
	for _, restrictedType := range accessDef.RestrictedTypes {
		graphEngineGranularAccessDefinition.RestrictedTypes = append(graphEngineGranularAccessDefinition.RestrictedTypes, graphengine.GranularAccessType{
			Name:   restrictedType.Name,
			Fields: restrictedType.Fields,
		})
	}

	return m.Spec.GraphEngine.ProcessGraphQLGranularAccess(w, r, graphEngineGranularAccessDefinition)
}

type GraphqlGranularAccessResult struct {
	failReason       GranularAccessFailReason
	validationResult *graphql.RequestFieldsValidationResult
	internalErr      error
}

type GraphqlGranularAccessChecker struct{}

func (g *GraphqlGranularAccessChecker) validateFieldRestrictions(gqlRequest *graphql.Request, fieldRestrictionList graphql.FieldRestrictionList, schema *graphql.Schema) GraphqlGranularAccessResult {
	result, err := gqlRequest.ValidateFieldRestrictions(schema, fieldRestrictionList, graphql.DefaultFieldsValidator{})
	if err != nil {
		return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonInternalError, internalErr: err}
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonValidationError, validationResult: &result}
	}
	return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonNone}
}

func (g *GraphqlGranularAccessChecker) CheckGraphqlRequestFieldAllowance(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) GraphqlGranularAccessResult {
	if len(accessDef.AllowedTypes) != 0 {
		fieldRestrictionList := graphql.FieldRestrictionList{
			Kind:  graphql.AllowList,
			Types: accessDef.AllowedTypes,
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, schema)
	}

	if len(accessDef.RestrictedTypes) != 0 {
		fieldRestrictionList := graphql.FieldRestrictionList{
			Kind:  graphql.BlockList,
			Types: accessDef.RestrictedTypes,
		}
		return g.validateFieldRestrictions(gqlRequest, fieldRestrictionList, schema)
	}

	// There are no restricted types. Every field is allowed access.
	return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonNone}
}
