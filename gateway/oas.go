package gateway

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	// Errors in patch
	errOASUnknown          = errors.New("unknown")
	errOASInvalidID        = errors.New("invalid api id")
	errOASNoSuchAPI        = errors.New("Can't find API with apiID, no such API")
	errOASRequestMalformed = errors.New("request malformed")
	errOASUseDBAppsConfig  = errors.New("Due to enabled use_db_apps_config, please use the Dashboard API")
	errOASIDDoesNotMatch   = errors.New("Request apiID does not match that in Definition! For Update operations these must match.")
)

const (
	msgErrOASValidationFailed = "Semantic validation for API Definition failed. Reason: %s"
)

// getApiID returns 'apiID' query parameter value and validity error (shared for consistency)
func getApiID(r *http.Request) (string, error) {
	id := mux.Vars(r)["apiID"]
	if id == "" {
		return "", errOASInvalidID
	}
	return id, nil
}

// logFromRequest returns a logger instance with fields from a http request
func logFromRequest(r *http.Request) *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"Method": r.Method,
		"Host":   r.Host,
		"URL":    r.URL.String(),
	})
}

// Some http response utilities, room for improvement

func (gw *Gateway) respondWithServerError(w http.ResponseWriter, r *http.Request, err error) {
	logFromRequest(r).WithError(err).Error("Internal server error")
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func (gw *Gateway) respondWithError(w http.ResponseWriter, r *http.Request, code int, err error) {
	logFromRequest(r).WithError(err).Errorf("Error handling request, status %d %s", code, http.StatusText(code))
	gw.respondWith(w, code, apiError(err.Error()))
}

func (gw *Gateway) respondWith(w http.ResponseWriter, code int, data interface{}) {
	doJSONWrite(w, code, data)
}

func (gw *Gateway) respond(w http.ResponseWriter, data interface{}) {
	doJSONWrite(w, http.StatusOK, data)
}
