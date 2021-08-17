package gateway

import (
	"errors"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/user"
)

type GranularAccessFailReason int

const (
	GranularAccessFailReasonNone GranularAccessFailReason = iota
	GranularAccessFailReasonInternalError
	GranularAccessFailReasonValidationError
)

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
	failReason, validationResult, err := checker.CheckGraphqlRequestFieldAllowance(gqlRequest, &accessDef, m.Spec.GraphQLExecutor.Schema)

	switch failReason {
	case GranularAccessFailReasonNone:
		return nil, http.StatusOK
	case GranularAccessFailReasonInternalError:
		m.Logger().Errorf("Error during GraphQL request restricted fields validation: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	case GranularAccessFailReasonValidationError:
		w.Header().Set(headers.ContentType, headers.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = validationResult.Errors.WriteResponse(w)
		m.Logger().Debugf("Error during GraphQL request restricted fields validation: '%s'", validationResult.Errors)
		return errCustomBodyResponse, http.StatusBadRequest
	}

	return nil, http.StatusOK
}

type GraphqlGranularAccessChecker struct{}

func (GraphqlGranularAccessChecker) CheckGraphqlRequestFieldAllowance(gqlRequest *graphql.Request, accessDef *user.AccessDefinition, schema *graphql.Schema) (failReason GranularAccessFailReason, validationResult *graphql.RequestFieldsValidationResult, err error) {
	if len(accessDef.RestrictedTypes) == 0 {
		return GranularAccessFailReasonNone, nil, nil
	}

	restrictedFieldsList := graphql.FieldRestrictionList{
		Kind:  graphql.BlockList,
		Types: accessDef.RestrictedTypes,
	}

	result, err := gqlRequest.ValidateFieldRestrictions(schema, restrictedFieldsList, graphql.DefaultFieldsValidator{})
	if err != nil {
		return GranularAccessFailReasonInternalError, nil, err
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		return GranularAccessFailReasonValidationError, &result, nil
	}

	return GranularAccessFailReasonNone, nil, nil
}
