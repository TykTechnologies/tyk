package main

import (
	"net/http"
	"strings"

	"github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/request"
)

type MiddlewareContextVars struct {
	BaseMiddleware
}

func (m *MiddlewareContextVars) Name() string {
	return "MiddlewareContextVars"
}

func (m *MiddlewareContextVars) EnabledForSpec() bool {
	return m.Spec.EnableContextVars
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MiddlewareContextVars) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	copiedRequest := copyRequest(r)
	contextDataObject := make(map[string]interface{})

	copiedRequest.ParseForm()

	// Form params (map[string][]string)
	contextDataObject["request_data"] = copiedRequest.Form

	contextDataObject["headers"] = map[string][]string(copiedRequest.Header)

	for hname, vals := range copiedRequest.Header {
		n := "headers_" + strings.Replace(hname, "-", "_", -1)
		contextDataObject[n] = vals[0]
	}
	contextDataObject["headers_Host"] = copiedRequest.Host

	// Path parts
	segmentedPathArray := strings.Split(copiedRequest.URL.Path, "/")
	contextDataObject["path_parts"] = segmentedPathArray

	// path data
	contextDataObject["path"] = copiedRequest.URL.Path

	// IP
	contextDataObject["remote_addr"] = request.RealIP(copiedRequest)

	//Correlation ID
	contextDataObject["request_id"] = uuid.NewV4().String()

	for _, c := range copiedRequest.Cookies() {
		name := "cookies_" + strings.Replace(c.Name, "-", "_", -1)
		contextDataObject[name] = c.Value
	}

	ctxSetData(r, contextDataObject)

	return nil, http.StatusOK
}
