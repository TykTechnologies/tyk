package main

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
	session := ctxGetSession(r)

	sessionVersionData, foundAPI := session.AccessRights[m.Spec.APIID]
	if !foundAPI {
		log.Debug("Version not found")
		return nil, http.StatusOK
	}

	if len(sessionVersionData.AllowedURLs) == 0 {
		log.Debug("No allowed URLS")
		return nil, http.StatusOK
	}

	for _, accessSpec := range sessionVersionData.AllowedURLs {
		log.Debug("Checking: ", r.URL.Path)
		log.Debug("Against: ", accessSpec.URL)
		asRegex, err := regexp.Compile(accessSpec.URL)
		if err != nil {
			log.Error("Regex error: ", err)
			return nil, http.StatusOK
		}

		match := asRegex.MatchString(r.URL.Path)
		if match {
			log.Debug("Match!")
			for _, method := range accessSpec.Methods {
				if method == r.Method {
					return nil, http.StatusOK
				}
			}
		}
	}

	token := ctxGetAuthToken(r)
	// No paths matched, disallow
	logEntry := getLogEntryForRequest(r, token, map[string]interface{}{"api_found": false})
	logEntry.Info("Attempted access to unauthorised endpoint (Granular).")

	return errors.New("Access to this resource has been disallowed"), http.StatusForbidden

}
