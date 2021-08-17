package gateway

import (
	"errors"
	"net/http"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/headers"
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

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	if len(sessionVersionData.RestrictedTypes) == 0 {
		return nil, http.StatusOK
	}

	gqlRequest := ctxGetGraphQLRequest(r)
	if gqlRequest == nil {
		return nil, http.StatusOK
	}

	restrictedFieldsList := graphql.FieldRestrictionList{
		Kind:  graphql.BlockList,
		Types: sessionVersionData.RestrictedTypes,
	}

	result, err := gqlRequest.ValidateFieldRestrictions(m.Spec.GraphQLExecutor.Schema, restrictedFieldsList, graphql.DefaultFieldsValidator{})
	if err != nil {
		m.Logger().Errorf("Error during GraphQL request restricted fields validation: '%s'", err)
		return errors.New("there was a problem proxying the request"), http.StatusInternalServerError
	}

	if !result.Valid || (result.Errors != nil && result.Errors.Count() > 0) {
		w.Header().Set(headers.ContentType, headers.ApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = result.Errors.WriteResponse(w)
		m.Logger().Debugf("Error during GraphQL request restricted fields validation: '%s'", result.Errors)
		return errCustomBodyResponse, http.StatusBadRequest
	}

	return nil, http.StatusOK
}
