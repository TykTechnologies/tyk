package main

import (
	"github.com/gorilla/context"
	"net/http"
	"strings"
)

type MiddlewareContextVars struct {
	*TykMiddleware
}

type MiddlewareContextVarsConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *MiddlewareContextVars) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *MiddlewareContextVars) GetConfig() (interface{}, error) {
	var thisModuleConfig MiddlewareContextVarsConfig
	return thisModuleConfig, nil
}

func (a *MiddlewareContextVars) IsEnabledForSpec() bool {
	if a.Spec.EnableContextVars {
		return true
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MiddlewareContextVars) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	if !m.Spec.EnableContextVars {
		return nil, 200
	}

	copiedRequest := CopyHttpRequest(r)
	contextDataObject := make(map[string]interface{})

	if copiedRequest != nil {
		copiedRequest.ParseForm()

		// Form params (map[string][]string)
		contextDataObject["request_data"] = copiedRequest.Form

		contextDataObject["headers"] = map[string][]string(copiedRequest.Header)

		for hname, vals := range copiedRequest.Header {
			n := "headers_" + strings.Replace(hname, "-", "_", -1)
			contextDataObject[n] = vals[0]
		}

		// Path parts
		segmentedPathArray := strings.Split(copiedRequest.URL.Path, "/")
		contextDataObject["path_parts"] = segmentedPathArray

		// path data
		contextDataObject["path"] = copiedRequest.URL.Path

		// IP:Port
		contextDataObject["remote_addr"] = copiedRequest.RemoteAddr
	}

	context.Set(r, ContextData, contextDataObject)

	return nil, 200
}
