package apispec

import (
	"net/http"
	"github.com/TykTechnologies/tyk/session"
)

type TykResponseHandler interface {
	Init(interface{}, *APISpec) error
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *session.SessionState) error
}
