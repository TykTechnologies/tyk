package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/v3/headers"

	"github.com/TykTechnologies/tyk/v3/regexp"
)

// GranularAccessMiddleware will check if a URL is specifically enabled for the key
type GranularAccessMiddleware struct {
	BaseMiddleware
}

func (m *GranularAccessMiddleware) Name() string {
	return "GranularAccessMiddleware"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *GranularAccessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := m.Logger()
	session := ctxGetSession(r)

	sessionVersionData, foundAPI := session.GetAccessRightByAPIID(m.Spec.APIID)
	if !foundAPI {
		return nil, http.StatusOK
	}

	if m.Spec.GraphQL.Enabled {
		if len(sessionVersionData.RestrictedTypes) == 0 {
			return nil, http.StatusOK
		}

		gqlRequest := ctxGetGraphQLRequest(r)

		result, err := gqlRequest.ValidateRestrictedFields(m.Spec.GraphQLExecutor.Schema, sessionVersionData.RestrictedTypes)
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

	if len(sessionVersionData.AllowedURLs) == 0 {
		return nil, http.StatusOK
	}

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		logger.Debug("Checking: ", r.URL.Path, " Against:", accessSpec.URL)
		asRegex, err := regexp.Compile(accessSpec.URL)
		if err != nil {
			logger.WithError(err).Error("Regex error")
			return nil, http.StatusOK
		}

		match := asRegex.MatchString(r.URL.Path)
		if match {
			logger.Debug("Match!")
			for _, method := range accessSpec.Methods {
				if method == r.Method {
					return nil, http.StatusOK
				}
			}
		}
	}

	logger.Info("Attempted access to unauthorised endpoint (Granular).")

	return errors.New("Access to this resource has been disallowed"), http.StatusForbidden

}
