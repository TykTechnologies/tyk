package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/httputil"
)

// GranularAccessMiddleware will check if a URL is specifically enabled for the key
type GranularAccessMiddleware struct {
	*BaseMiddleware
}

func (m *GranularAccessMiddleware) Name() string {
	return "GranularAccessMiddleware"
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *GranularAccessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := m.Logger().WithField("path", r.URL.Path)
	session := ctxGetSession(r)

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		return nil, http.StatusOK
	}

	if len(sessionVersionData.AllowedURLs) == 0 {
		return nil, http.StatusOK
	}

	urlPath := m.Spec.StripListenPath(r.URL.Path)

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		url := accessSpec.URL
		match, err := httputil.MatchEndpoint(url, urlPath)
		if err != nil {
			logger.WithError(err).Errorf("error matching path regex: %q, skipping", url)
			continue
		}

		if !match {
			continue
		}

		logger.WithField("pattern", url).WithField("match", match).Debug("checking allowed url")

		// if a path is matched, but isn't matched on method,
		// then we continue onto the next path for evaluation.
		for _, method := range accessSpec.Methods {
			if method == r.Method {
				return nil, http.StatusOK
			}
		}
	}

	logger.Info("Attempted access to unauthorised endpoint (Granular).")

	return errors.New("Access to this resource has been disallowed"), http.StatusForbidden

}
