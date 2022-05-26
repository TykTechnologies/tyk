package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/regexp"
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

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	if len(sessionVersionData.AllowedURLs) == 0 {
		return nil, http.StatusOK
	}

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		if log.Level == DebugLevel {
			logger.Debug("Checking: ", r.URL.Path, " Against:", accessSpec.URL)
		}
		asRegex, err := regexp.Compile(accessSpec.URL)
		if err != nil {
			logger.WithError(err).Error("Regex error")
			return nil, http.StatusOK
		}

		match := asRegex.MatchString(r.URL.Path)
		if match {
			if log.Level == DebugLevel {
				logger.Debug("Match!")
			}
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
