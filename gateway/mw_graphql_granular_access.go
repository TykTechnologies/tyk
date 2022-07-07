package gateway

import (
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/headers"
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
	BaseMiddleware
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

	gqlRequest := ctxGetGraphQLRequest(r)
	if gqlRequest == nil {
		return nil, http.StatusOK
	}

	checker := &GraphqlGranularAccessChecker{}
	result := checker.CheckGraphqlRequestFieldAllowance(gqlRequest, &accessDef, m.Spec.GraphQLExecutor.Schema)

	switch result.failReason {
	case GranularAccessFailReasonNone:
		return nil, http.StatusOK
	case GranularAccessFailReasonInternalError:
		m.Logger().Errorf(RestrictedFieldValidationFailedLogMsg, result.internalErr)
		return ProxyingRequestFailedErr, http.StatusInternalServerError
	case GranularAccessFailReasonValidationError:
		w.Header().Set(headers.ContentType, headers.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = result.validationResult.Errors.WriteResponse(w)
		m.Logger().Debugf(RestrictedFieldValidationFailedLogMsg, result.validationResult.Errors)
		return errCustomBodyResponse, http.StatusBadRequest
	}

	return nil, http.StatusOK
}

type GraphqlGranularAccessResult struct {
	failReason       GranularAccessFailReason
	validationResult *graphql.RequestFieldsValidationResult
	internalErr      error
}

type GraphqlGranularAccessChecker struct{}

func (GraphqlGranularAccessChecker) CheckGraphqlRequestFieldAllowance(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) GraphqlGranularAccessResult {
	if len(accessDef.RestrictedTypes) == 0 {
		return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonNone}
	}

	restrictedFieldsList := graphql.FieldRestrictionList{
		Kind:  graphql.BlockList,
		Types: accessDef.RestrictedTypes,
	}

	result, err := gqlRequest.ValidateFieldRestrictions(schema, restrictedFieldsList, graphql.DefaultFieldsValidator{})
	if err != nil {
		return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonInternalError, internalErr: err}
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonValidationError, validationResult: &result}
	}

	return GraphqlGranularAccessResult{failReason: GranularAccessFailReasonNone}
}
